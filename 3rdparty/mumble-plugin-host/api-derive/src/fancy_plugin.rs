//! `#[fancy_plugin]` attribute implementation.
//!
//! Walks an `impl MumblePlugin for X` block and:
//!
//! * Extracts the impl-position `plugin_info! { ... }` invocation
//!   tokens and reuses them inside a synthesised `fn info_json`.
//! * Collects `#[command]`-tagged methods, building per-method
//!   slash-command manifest entries and an inherent dispatch table.
//! * Generates `fn name`, `fn version`, `fn info_json`, and (if the
//!   user didn't write one) `fn on_plugin_message`.  When the user
//!   *did* write `fn on_plugin_message`, the dispatch prelude is
//!   inserted at the top of their existing body.
//! * Emits a sibling inherent impl with the auto-generated
//!   `__fancy_auto_slash_commands` and `__fancy_dispatch` helpers.
//!
//! Plugin authors must provide one accessor on the plugin type
//! (outside the trait impl) so the dispatcher can ship responses.
//! Callback-style because `PluginContext_TO` is not `Clone`:
//!
//! ```ignore
//! impl MyPlugin {
//!     fn with_ctx<R>(
//!         &self,
//!         f: impl FnOnce(&PluginContext_TO<RArc<()>>) -> R,
//!     ) -> Option<R> {
//!         /* run `f` with a borrow of the stored trait object, or None when not loaded */
//!     }
//! }
//! ```

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse2, parse_quote, Attribute, Expr, FnArg, GenericArgument, Ident, ImplItem, ImplItemFn,
    ItemImpl, Lit, Meta, Pat, PathArguments, ReturnType, Type, TypePath,
};

use crate::command::CommandArgs;
use crate::component::ComponentArgs;
use crate::modal::ModalArgs;

pub(crate) fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args = FancyPluginArgs::parse(args)?;
    let mut input: ItemImpl = parse2(item)?;

    // Pull the self-type ident so we can attach an inherent impl with
    // the right path even when there are generic parameters.
    let self_ty = input.self_ty.clone();

    let Walked {
        plugin_info_tokens,
        commands,
        mut components,
        mut modals,
        user_on_plugin_message,
        kept_items,
        moved_methods,
    } = walk_impl(&mut input)?;

    let self_ty_ident = extract_self_ty_ident(&self_ty)?;
    finalize_auto_ids(&mut components, &mut modals, &self_ty_ident)?;

    let name_expr = &args.name;
    let version_expr = args
        .version
        .clone()
        .unwrap_or_else(|| parse_quote!(::std::env!("CARGO_PKG_VERSION")));

    let info_json_fn = build_info_json_fn(plugin_info_tokens.as_ref());
    let name_fn = build_name_fn(name_expr);
    let version_fn = build_version_fn(&version_expr);
    let on_msg_fn = build_on_plugin_message_fn(user_on_plugin_message);
    let auto_cmds_fn = build_auto_slash_commands_fn(&commands);
    let dispatch_fn = build_dispatch_fn(&commands, &components, &modals);
    let id_consts = build_id_consts(&commands, &components, &modals);
    let no_desc_warnings = build_no_description_warnings(&commands, &self_ty);

    // Reassemble the trait impl with the user's surviving items plus
    // the synthesised trait methods.  Order: user items first so any
    // helper inherent calls they make resolve as written, then the
    // generated trait methods.
    input.items = kept_items;
    input.items.push(ImplItem::Fn(name_fn));
    input.items.push(ImplItem::Fn(version_fn));
    input.items.push(ImplItem::Fn(info_json_fn));
    input.items.push(ImplItem::Fn(on_msg_fn));

    Ok(quote! {
        #input

        #[allow(non_snake_case, reason = "macro-generated identifiers are namespaced with __fancy_")]
        const _: () = {
            #no_desc_warnings
        };

        impl #self_ty {
            #( #moved_methods )*
            #auto_cmds_fn
            #dispatch_fn
            #id_consts
        }
    })
}

// ---------------------------------------------------------------------------
// Attribute args
// ---------------------------------------------------------------------------

struct FancyPluginArgs {
    name: Expr,
    version: Option<Expr>,
}

impl FancyPluginArgs {
    fn parse(tokens: TokenStream) -> syn::Result<Self> {
        let mut name: Option<Expr> = None;
        let mut version: Option<Expr> = None;
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("name") {
                let value: Expr = meta.value()?.parse()?;
                if name.is_some() {
                    return Err(meta.error("duplicate `name` argument"));
                }
                name = Some(value);
                Ok(())
            } else if meta.path.is_ident("version") {
                let value: Expr = meta.value()?.parse()?;
                if version.is_some() {
                    return Err(meta.error("duplicate `version` argument"));
                }
                version = Some(value);
                Ok(())
            } else {
                Err(meta.error("unknown #[fancy_plugin] argument (accepted: name, version)"))
            }
        });
        syn::parse::Parser::parse2(parser, tokens)?;
        let Some(name) = name else {
            return Err(syn::Error::new(
                Span::call_site(),
                "#[fancy_plugin] requires a `name` argument \
                 (e.g. `#[fancy_plugin(name = \"fancy-greeter\")]`)",
            ));
        };
        Ok(Self { name, version })
    }
}

// ---------------------------------------------------------------------------
// Impl-block walker
// ---------------------------------------------------------------------------

struct Walked {
    plugin_info_tokens: Option<TokenStream>,
    commands: Vec<Command>,
    components: Vec<ComponentHandler>,
    modals: Vec<ModalHandler>,
    user_on_plugin_message: Option<ImplItemFn>,
    /// Items that survive into the trait impl unchanged.
    kept_items: Vec<ImplItem>,
    /// Handler methods (`#[command]`, `#[component]`, `#[modal]`)
    /// lifted out of the trait impl into the inherent impl alongside
    /// the auto-generated dispatch helpers.  (Rust forbids non-trait
    /// methods inside a trait impl, so we move them.)
    moved_methods: Vec<ImplItemFn>,
}

fn walk_impl(input: &mut ItemImpl) -> syn::Result<Walked> {
    let mut plugin_info_tokens: Option<TokenStream> = None;
    let mut commands: Vec<Command> = Vec::new();
    let mut components: Vec<ComponentHandler> = Vec::new();
    let mut modals: Vec<ModalHandler> = Vec::new();
    let mut moved_methods: Vec<ImplItemFn> = Vec::new();
    let mut user_on_plugin_message: Option<ImplItemFn> = None;
    let mut kept_items: Vec<ImplItem> = Vec::new();

    // Take ownership of items so we can move them out selectively.
    let items = std::mem::take(&mut input.items);
    for item in items {
        match item {
            // Impl-position macros: only `plugin_info! { ... }` is recognised.
            ImplItem::Macro(m) => {
                if m.mac.path.is_ident("plugin_info") {
                    if plugin_info_tokens.is_some() {
                        return Err(syn::Error::new_spanned(
                            &m.mac,
                            "duplicate `plugin_info!` invocation inside #[fancy_plugin]",
                        ));
                    }
                    plugin_info_tokens = Some(m.mac.tokens.clone());
                } else {
                    return Err(syn::Error::new_spanned(
                        &m.mac.path,
                        "unexpected item-position macro inside #[fancy_plugin] impl block \
                         (only `plugin_info! { ... }` is recognised)",
                    ));
                }
            }
            // Functions: classify as command / component / modal /
            // on_plugin_message / forbidden override (name/version/
            // info_json) / passthrough.
            ImplItem::Fn(mut f) => {
                let ident = f.sig.ident.clone();
                if ident == "name" || ident == "version" || ident == "info_json" {
                    return Err(syn::Error::new_spanned(
                        &f.sig.ident,
                        format!(
                            "#[fancy_plugin] generates `fn {ident}`; \
                             remove this definition or drop the attribute"
                        ),
                    ));
                }
                if ident == "on_plugin_message" {
                    if user_on_plugin_message.is_some() {
                        return Err(syn::Error::new_spanned(
                            &f.sig.ident,
                            "duplicate `fn on_plugin_message`",
                        ));
                    }
                    user_on_plugin_message = Some(f);
                    continue;
                }
                // Reject overlapping attributes up front so we don't
                // emit confusing "duplicate id" errors later.
                let cmd_idx = f.attrs.iter().position(|a| a.path().is_ident("command"));
                let comp_idx = f.attrs.iter().position(|a| a.path().is_ident("component"));
                let modal_idx = f.attrs.iter().position(|a| a.path().is_ident("modal"));
                let tagged = [cmd_idx.is_some(), comp_idx.is_some(), modal_idx.is_some()]
                    .iter()
                    .filter(|x| **x)
                    .count();
                if tagged > 1 {
                    return Err(syn::Error::new_spanned(
                        &f.sig.ident,
                        "a method may carry at most one of \
                         #[command] / #[component] / #[modal]",
                    ));
                }
                if let Some(idx) = cmd_idx {
                    let attr = f.attrs.remove(idx);
                    let cmd = parse_command(&attr, &f)?;
                    strip_param_macro_attrs(&mut f);
                    commands.push(cmd);
                    moved_methods.push(f);
                } else if let Some(idx) = comp_idx {
                    let attr = f.attrs.remove(idx);
                    let comp = parse_component(&attr, &f)?;
                    strip_param_macro_attrs(&mut f);
                    components.push(comp);
                    moved_methods.push(f);
                } else if let Some(idx) = modal_idx {
                    let attr = f.attrs.remove(idx);
                    let m = parse_modal(&attr, &f)?;
                    strip_param_macro_attrs(&mut f);
                    modals.push(m);
                    moved_methods.push(f);
                } else {
                    kept_items.push(ImplItem::Fn(f));
                }
            }
            other => kept_items.push(other),
        }
    }

    // Reject duplicate command names early - simpler error than
    // "duplicate variant" coming out of the synthesised match.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in &commands {
        if let Some(name) = &c.literal_name {
            if !seen.insert(name.clone()) {
                return Err(syn::Error::new_spanned(
                    &c.method_ident,
                    format!("duplicate slash-command name `{name}`"),
                ));
            }
        }
    }

    Ok(Walked {
        plugin_info_tokens,
        commands,
        components,
        modals,
        user_on_plugin_message,
        kept_items,
        moved_methods,
    })
}

/// Remove `#[option(...)]` and `#[doc = "..."]` attributes from the
/// parameters of a method.  Called after metadata extraction so the
/// re-emitted method body doesn't carry attributes rustc would reject
/// (`#[option]` is unknown to it; `#[doc]` on params is silently
/// ignored but worth keeping the AST clean).
fn strip_param_macro_attrs(f: &mut ImplItemFn) {
    for arg in f.sig.inputs.iter_mut() {
        if let FnArg::Typed(pt) = arg {
            pt.attrs.retain(|a| {
                !a.path().is_ident("option")
                    && !a.path().is_ident("field")
                    && !a.path().is_ident("doc")
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Per-command extraction
// ---------------------------------------------------------------------------

struct Command {
    method_ident: Ident,
    /// Expression for the command name, as supplied via `#[command(name = ...)]`.
    name_expr: Expr,
    /// When `name_expr` is a string literal, the resolved value -
    /// used for the dispatch match arms and duplicate detection.
    /// `None` for non-literal name expressions (the dispatcher uses
    /// runtime comparison against the expr value in that case).
    literal_name: Option<String>,
    /// Description expression (string literal, ident, or `&str` expr).
    /// `None` if absent and there's no doc-comment fallback either.
    description_expr: Option<Expr>,
    /// Typed parameters in declaration order.
    params: Vec<CommandParam>,
}

struct CommandParam {
    ident: Ident,
    description: String,
    type_kind: OptionTypeKind,
    is_optional: bool,
    /// Original syn type tokens, for the dispatch shim's extract_option turbofish.
    extract_ty: TokenStream,
}

#[derive(Clone, Copy)]
enum OptionTypeKind {
    String,
    Boolean,
    Integer,
}

impl OptionTypeKind {
    fn manifest_variant(self) -> TokenStream {
        match self {
            Self::String => quote!(::mumble_plugin_api::OptionType::String),
            Self::Boolean => quote!(::mumble_plugin_api::OptionType::Boolean),
            Self::Integer => quote!(::mumble_plugin_api::OptionType::Integer),
        }
    }
}

fn parse_command(attr: &Attribute, method: &ImplItemFn) -> syn::Result<Command> {
    // Re-parse the attribute args via the shared parser in command.rs.
    let args_tokens = match &attr.meta {
        Meta::List(list) => list.tokens.clone(),
        Meta::Path(_) => TokenStream::new(),
        Meta::NameValue(_) => {
            return Err(syn::Error::new_spanned(
                attr,
                "#[command] arguments must be in parentheses: #[command(name = \"...\")]",
            ));
        }
    };
    let CommandArgs { name, description } = CommandArgs::parse(args_tokens)?;

    let literal_name = expr_as_string_lit(&name);
    let description_expr =
        description.or_else(|| extract_doc_string(&method.attrs).map(|s| parse_quote!(#s)));

    let params = method
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Receiver(_) => None,
            FnArg::Typed(pt) => Some(pt),
        })
        .map(parse_command_param)
        .collect::<syn::Result<Vec<_>>>()?;

    // Sanity-check return type.  We don't enforce the exact type to
    // keep the door open for `-> impl Into<InteractionResponse>`, but
    // a missing return type is almost certainly wrong.
    if matches!(method.sig.output, ReturnType::Default) {
        return Err(syn::Error::new_spanned(
            &method.sig,
            "#[command] methods must return `InteractionResponse` \
             (or any type convertible into one)",
        ));
    }

    Ok(Command {
        method_ident: method.sig.ident.clone(),
        name_expr: name,
        literal_name,
        description_expr,
        params,
    })
}

fn parse_command_param(pt: &syn::PatType) -> syn::Result<CommandParam> {
    let ident = match &*pt.pat {
        Pat::Ident(p) => p.ident.clone(),
        _ => {
            return Err(syn::Error::new_spanned(
                &pt.pat,
                "#[command] parameters must be plain `name: Type` bindings (no patterns)",
            ));
        }
    };
    let (type_kind, is_optional, extract_ty) = classify_param_type(&pt.ty)?;
    let description = extract_param_description(&pt.attrs).unwrap_or_default();
    Ok(CommandParam {
        ident,
        description,
        type_kind,
        is_optional,
        extract_ty,
    })
}

/// Classify a parameter type into the wire-side `OptionType` it
/// maps to, plus whether it's `Option<T>` (manifest required=false),
/// plus the token stream to use as `extract_option::<TY>(...)`.
fn classify_param_type(ty: &Type) -> syn::Result<(OptionTypeKind, bool, TokenStream)> {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return Err(unsupported_type_error(ty));
    };
    let last = path
        .segments
        .last()
        .ok_or_else(|| unsupported_type_error(ty))?;
    let extract_ty = quote!(#ty);

    // Match Option<T> specifically: recurse on inner T for the
    // OptionType classification.
    if last.ident == "Option" {
        if let PathArguments::AngleBracketed(ab) = &last.arguments {
            if let Some(GenericArgument::Type(inner)) = ab.args.first() {
                let (kind, inner_optional, _) = classify_param_type(inner)?;
                if inner_optional {
                    return Err(syn::Error::new_spanned(
                        ty,
                        "nested `Option<Option<...>>` is not supported for #[command] params",
                    ));
                }
                return Ok((kind, true, extract_ty));
            }
        }
        return Err(unsupported_type_error(ty));
    }

    let kind = match last.ident.to_string().as_str() {
        "String" => OptionTypeKind::String,
        "bool" => OptionTypeKind::Boolean,
        "i64" | "u32" => OptionTypeKind::Integer,
        _ => return Err(unsupported_type_error(ty)),
    };
    Ok((kind, false, extract_ty))
}

fn unsupported_type_error(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(
        ty,
        "unsupported parameter type for #[command]: \
         expected one of `String`, `bool`, `i64`, `u32`, or `Option<T>` of those",
    )
}

/// Extract a description from `#[option(description = "...")]` on a
/// parameter, falling back to any doc-comment on the parameter.
fn extract_param_description(attrs: &[Attribute]) -> Option<String> {
    // First: explicit #[option(description = "...")].
    for attr in attrs {
        if !attr.path().is_ident("option") {
            continue;
        }
        let mut found: Option<String> = None;
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("description") {
                let value: Expr = meta.value()?.parse()?;
                if let Some(s) = expr_as_string_lit(&value) {
                    found = Some(s);
                    Ok(())
                } else {
                    Err(meta.error("`description` must be a string literal"))
                }
            } else {
                Err(meta.error("unknown #[option] argument (accepted: description)"))
            }
        });
        let attr_tokens = match &attr.meta {
            Meta::List(list) => list.tokens.clone(),
            _ => TokenStream::new(),
        };
        if syn::parse::Parser::parse2(parser, attr_tokens).is_ok() {
            if let Some(s) = found {
                return Some(s);
            }
        }
    }
    // Fallback: doc-comments on the parameter (Rust accepts these in
    // stable; they're just ignored by rustdoc).
    extract_doc_string(attrs)
}

fn extract_doc_string(attrs: &[Attribute]) -> Option<String> {
    let mut parts = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let Meta::NameValue(nv) = &attr.meta {
            if let Expr::Lit(syn::ExprLit {
                lit: Lit::Str(s), ..
            }) = &nv.value
            {
                parts.push(s.value().trim().to_owned());
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn expr_as_string_lit(e: &Expr) -> Option<String> {
    if let Expr::Lit(syn::ExprLit {
        lit: Lit::Str(s), ..
    }) = e
    {
        Some(s.value())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Codegen for trait methods
// ---------------------------------------------------------------------------

fn build_name_fn(name_expr: &Expr) -> ImplItemFn {
    parse_quote! {
        fn name(&self) -> ::abi_stable::std_types::RStr<'_> {
            ::abi_stable::std_types::RStr::from_str(#name_expr)
        }
    }
}

fn build_version_fn(version_expr: &Expr) -> ImplItemFn {
    parse_quote! {
        fn version(&self) -> ::abi_stable::std_types::RStr<'_> {
            ::abi_stable::std_types::RStr::from_str(#version_expr)
        }
    }
}

fn build_info_json_fn(plugin_info_tokens: Option<&TokenStream>) -> ImplItemFn {
    let body = match plugin_info_tokens {
        Some(tokens) => quote! {
            #[allow(unused_mut, reason = "auto-mutated only when commands are registered")]
            let mut __info = ::mumble_plugin_api::plugin_info! { #tokens };
            let __cmds = Self::__fancy_auto_slash_commands();
            if !__cmds.is_empty() {
                let __m = __info
                    .client_manifest
                    .get_or_insert_with(<::mumble_plugin_api::ClientManifest as ::std::default::Default>::default);
                __m.slash_commands.extend(__cmds);
            }
            __info.to_rstring()
        },
        None => quote! {
            let __cmds = Self::__fancy_auto_slash_commands();
            if __cmds.is_empty() {
                return ::abi_stable::std_types::RString::from("{}");
            }
            let mut __info = ::mumble_plugin_api::PluginInfo {
                description: ::std::string::String::new(),
                author: ::std::option::Option::None,
                homepage: ::std::option::Option::None,
                tags: ::std::vec::Vec::new(),
                debug_info: ::std::vec::Vec::new(),
                client_manifest: ::std::option::Option::Some(
                    ::mumble_plugin_api::ClientManifest {
                        slash_commands: __cmds,
                        ..<::mumble_plugin_api::ClientManifest as ::std::default::Default>::default()
                    },
                ),
            };
            __info.to_rstring()
        },
    };
    parse_quote! {
        fn info_json(&self) -> ::abi_stable::std_types::RString {
            #body
        }
    }
}

fn build_on_plugin_message_fn(user: Option<ImplItemFn>) -> ImplItemFn {
    // The dispatch prelude calls `self.with_ctx(...)` so plugin
    // authors do not have to clone the (non-Clone) `PluginContext_TO`
    // out of their inner state.  See the `#[fancy_plugin]` module
    // docs for the required accessor signature.
    let dispatch_prelude = quote! {
        if let ::std::option::Option::Some(__response) = self.__fancy_dispatch(&msg) {
            let __sent = self.with_ctx(|__ctx| {
                ::mumble_plugin_api::send_interaction_response(__ctx, &msg, __response);
            });
            if __sent.is_none() {
                ::std::eprintln!(
                    "[mumble-plugin-api] dispatched command produced a response but \
                     `self.with_ctx(..)` returned None; response dropped"
                );
            }
            return ::abi_stable::std_types::RResult::ROk(());
        }
    };

    match user {
        Some(mut f) => {
            // Splice the prelude in at the top of the user's body.
            let user_stmts = std::mem::take(&mut f.block.stmts);
            let new_block: syn::Block = parse_quote! {{
                #dispatch_prelude
                #(#user_stmts)*
            }};
            f.block = new_block;
            f
        }
        None => parse_quote! {
            fn on_plugin_message(
                &self,
                msg: ::mumble_plugin_api::PluginMessageIn,
            ) -> ::mumble_plugin_api::PluginResult<()> {
                #dispatch_prelude
                ::abi_stable::std_types::RResult::ROk(())
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Codegen for inherent helpers
// ---------------------------------------------------------------------------

fn build_auto_slash_commands_fn(commands: &[Command]) -> TokenStream {
    let entries = commands.iter().map(|c| {
        let name_expr = &c.name_expr;
        let description_expr = c
            .description_expr
            .clone()
            .unwrap_or_else(|| parse_quote!(""));
        let opts = c.params.iter().map(|p| {
            let pname = p.ident.to_string();
            let pdesc = &p.description;
            let ptype = p.type_kind.manifest_variant();
            let prequired = !p.is_optional;
            quote! {
                ::mumble_plugin_api::SlashCommandOption {
                    name: ::std::string::String::from(#pname),
                    description: ::std::string::String::from(#pdesc),
                    option_type: #ptype,
                    required: #prequired,
                    choices: ::std::vec::Vec::new(),
                }
            }
        });
        quote! {
            ::mumble_plugin_api::SlashCommand {
                name: ::std::string::String::from(#name_expr),
                description: ::std::string::String::from(#description_expr),
                options: ::std::vec![ #(#opts),* ],
            }
        }
    });

    quote! {
        #[doc(hidden)]
        #[allow(non_snake_case, reason = "macro-generated identifier")]
        fn __fancy_auto_slash_commands() -> ::std::vec::Vec<::mumble_plugin_api::SlashCommand> {
            ::std::vec![ #(#entries),* ]
        }
    }
}

fn build_dispatch_fn(
    commands: &[Command],
    components: &[ComponentHandler],
    modals: &[ModalHandler],
) -> TokenStream {
    let command_arms = commands.iter().map(|c| {
        let method = &c.method_ident;
        let name_expr = &c.name_expr;
        let extractions = c.params.iter().map(|p| {
            let pident = &p.ident;
            let pname = p.ident.to_string();
            let ty = &p.extract_ty;
            quote! {
                let #pident = match ::mumble_plugin_api::extract_option::<#ty>(__opts, #pname) {
                    ::std::result::Result::Ok(v) => v,
                    ::std::result::Result::Err(e) => {
                        ::std::eprintln!(
                            "[mumble-plugin-api] command argument extraction failed: {e}"
                        );
                        return ::std::option::Option::Some(
                            ::mumble_plugin_api::InteractionResponse::toast(
                                ::std::format!("command argument error: {e}"),
                            )
                            .with_toast_level(::mumble_plugin_api::ToastLevel::Error)
                            .with_correlation_id(__correlation_id.to_owned()),
                        );
                    }
                };
            }
        });
        let arg_idents = c.params.iter().map(|p| &p.ident);
        quote! {
            __name if __name == ::std::convert::AsRef::<str>::as_ref(#name_expr) => {
                #(#extractions)*
                let mut __resp = self.#method( #(#arg_idents),* );
                if __resp.correlation_id.is_none() {
                    __resp.correlation_id = ::std::option::Option::Some(__correlation_id.to_owned());
                }
                ::std::option::Option::Some(__resp)
            }
        }
    });

    let component_arms = components.iter().map(|c| {
        let method = &c.method_ident;
        let id_expr = &c.custom_id_expr;
        let call = match c.values_binding {
            ComponentValuesBinding::None => quote! { self.#method() },
            ComponentValuesBinding::Values => quote! {
                self.#method(__values.iter().map(::std::string::ToString::to_string).collect::<::std::vec::Vec<::std::string::String>>())
            },
        };
        quote! {
            __cid if __cid == ::std::convert::AsRef::<str>::as_ref(#id_expr) => {
                let mut __resp = #call;
                if __resp.correlation_id.is_none() {
                    __resp.correlation_id = ::std::option::Option::Some(__correlation_id.to_owned());
                }
                ::std::option::Option::Some(__resp)
            }
        }
    });

    let modal_arms = modals.iter().map(|m| {
        let method = &m.method_ident;
        let id_expr = &m.custom_id_expr;
        let extractions = m.fields.iter().map(|f| {
            let pident = &f.ident;
            let pname = f.ident.to_string();
            let ty = &f.extract_ty;
            quote! {
                let #pident = match ::mumble_plugin_api::extract_field::<#ty>(__values, #pname) {
                    ::std::result::Result::Ok(v) => v,
                    ::std::result::Result::Err(e) => {
                        ::std::eprintln!(
                            "[mumble-plugin-api] modal field extraction failed: {e}"
                        );
                        return ::std::option::Option::Some(
                            ::mumble_plugin_api::InteractionResponse::toast(
                                ::std::format!("modal field error: {e}"),
                            )
                            .with_toast_level(::mumble_plugin_api::ToastLevel::Error)
                            .with_correlation_id(__correlation_id.to_owned()),
                        );
                    }
                };
            }
        });
        let arg_idents = m.fields.iter().map(|f| &f.ident);
        quote! {
            __cid if __cid == ::std::convert::AsRef::<str>::as_ref(#id_expr) => {
                #(#extractions)*
                let mut __resp = self.#method( #(#arg_idents),* );
                if __resp.correlation_id.is_none() {
                    __resp.correlation_id = ::std::option::Option::Some(__correlation_id.to_owned());
                }
                ::std::option::Option::Some(__resp)
            }
        }
    });

    quote! {
        #[doc(hidden)]
        #[allow(non_snake_case, reason = "macro-generated identifier")]
        fn __fancy_dispatch(
            &self,
            __msg: &::mumble_plugin_api::PluginMessageIn,
        ) -> ::std::option::Option<::mumble_plugin_api::InteractionResponse> {
            if __msg.payload_type.as_str() != ::mumble_plugin_api::INTERACTION_PAYLOAD_TYPE {
                return ::std::option::Option::None;
            }
            let __interaction = ::mumble_plugin_api::parse_interaction(__msg)?;
            let __correlation_id = __interaction.correlation_id.clone();
            let __correlation_id: &::std::primitive::str = __correlation_id.as_str();
            match &__interaction.kind {
                ::mumble_plugin_api::InteractionKind::SlashCommand { name, options, .. } => {
                    let __name: &str = name.as_str();
                    let __opts = options;
                    let _ = __opts;
                    match __name {
                        #(#command_arms)*
                        _ => ::std::option::Option::None,
                    }
                }
                ::mumble_plugin_api::InteractionKind::Component { custom_id, values, .. } => {
                    let __cid: &str = custom_id.as_str();
                    let __values = values;
                    let _ = __values;
                    match __cid {
                        #(#component_arms)*
                        _ => ::std::option::Option::None,
                    }
                }
                ::mumble_plugin_api::InteractionKind::ModalSubmit { custom_id, values, .. } => {
                    let __cid: &str = custom_id.as_str();
                    let __values = values;
                    let _ = __values;
                    match __cid {
                        #(#modal_arms)*
                        _ => ::std::option::Option::None,
                    }
                }
            }
        }
    }
}

/// Emit `#[deprecated]` const markers for commands that have neither
/// an explicit `description = "..."` nor a doc-comment fallback.  The
/// const is referenced inline below it, so the deprecation lint
/// fires at the call site with a useful message.  Only emits markers
/// for commands missing descriptions; commands with descriptions
/// produce no output.
fn build_no_description_warnings(commands: &[Command], _self_ty: &Type) -> TokenStream {
    let warns = commands.iter().filter_map(|c| {
        if c.description_expr.is_some() {
            return None;
        }
        let warn_ident = format_ident!("__fancy_warn_no_description_{}", c.method_ident);
        let cmd_name = c
            .literal_name
            .clone()
            .unwrap_or_else(|| c.method_ident.to_string());
        let note = format!(
            "command `{cmd_name}` has no description: add a doc-comment to fn `{}` \
             or pass `description = \"...\"` to #[command]",
            c.method_ident
        );
        Some(quote_spanned!(c.method_ident.span()=> {
            #[deprecated = #note]
            #[allow(non_upper_case_globals, reason = "macro-generated marker")]
            const #warn_ident: () = ();
            let _ = #warn_ident;
        }))
    });
    quote! { #( #warns )* }
}

// ---------------------------------------------------------------------------
// Component / Modal extraction
// ---------------------------------------------------------------------------

struct ComponentHandler {
    method_ident: Ident,
    /// Expression that evaluates to the wire `custom_id`.  Either the
    /// explicit `custom_id = ...` attribute value, or an
    /// auto-generated string literal `"<TypeName>::<method>"`.
    custom_id_expr: Expr,
    /// When `custom_id_expr` is a string literal, the resolved value
    /// (used for duplicate detection).
    literal_custom_id: Option<String>,
    /// Whether the handler takes a `values: Vec<String>` parameter.
    values_binding: ComponentValuesBinding,
}

#[derive(Clone, Copy)]
enum ComponentValuesBinding {
    None,
    Values,
}

struct ModalHandler {
    method_ident: Ident,
    custom_id_expr: Expr,
    literal_custom_id: Option<String>,
    fields: Vec<ModalField>,
}

struct ModalField {
    ident: Ident,
    /// Original syn type tokens, for `extract_field::<TY>(...)`.
    extract_ty: TokenStream,
}

fn parse_component(attr: &Attribute, method: &ImplItemFn) -> syn::Result<ComponentHandler> {
    let args_tokens = match &attr.meta {
        Meta::List(list) => list.tokens.clone(),
        Meta::Path(_) => TokenStream::new(),
        Meta::NameValue(_) => {
            return Err(syn::Error::new_spanned(
                attr,
                "#[component] arguments must be in parentheses: #[component(custom_id = \"...\")]",
            ));
        }
    };
    let ComponentArgs { custom_id } = ComponentArgs::parse(args_tokens)?;

    let (custom_id_expr, literal_custom_id) = match custom_id {
        Some(e) => {
            let lit = expr_as_string_lit(&e);
            (e, lit)
        }
        None => {
            let auto = auto_custom_id_for(method);
            (parse_quote!(#auto), Some(auto))
        }
    };

    if matches!(method.sig.output, ReturnType::Default) {
        return Err(syn::Error::new_spanned(
            &method.sig,
            "#[component] methods must return `InteractionResponse`",
        ));
    }

    // Classify the non-self parameter list: either zero params or a
    // single `Vec<String>` named `values`.
    let typed: Vec<&syn::PatType> = method
        .sig
        .inputs
        .iter()
        .filter_map(|i| match i {
            FnArg::Typed(pt) => Some(pt),
            FnArg::Receiver(_) => None,
        })
        .collect();
    let values_binding = match typed.as_slice() {
        [] => ComponentValuesBinding::None,
        [pt] => {
            if !type_is_vec_string(&pt.ty) {
                return Err(syn::Error::new_spanned(
                    &pt.ty,
                    "#[component] methods accept either no parameters or a single \
                     `Vec<String>` parameter",
                ));
            }
            ComponentValuesBinding::Values
        }
        _ => {
            return Err(syn::Error::new_spanned(
                &method.sig.inputs,
                "#[component] methods accept either no parameters or a single \
                 `Vec<String>` parameter",
            ));
        }
    };

    Ok(ComponentHandler {
        method_ident: method.sig.ident.clone(),
        custom_id_expr,
        literal_custom_id,
        values_binding,
    })
}

fn parse_modal(attr: &Attribute, method: &ImplItemFn) -> syn::Result<ModalHandler> {
    let args_tokens = match &attr.meta {
        Meta::List(list) => list.tokens.clone(),
        Meta::Path(_) => TokenStream::new(),
        Meta::NameValue(_) => {
            return Err(syn::Error::new_spanned(
                attr,
                "#[modal] arguments must be in parentheses: #[modal(custom_id = \"...\")]",
            ));
        }
    };
    let ModalArgs { custom_id } = ModalArgs::parse(args_tokens)?;

    let (custom_id_expr, literal_custom_id) = match custom_id {
        Some(e) => {
            let lit = expr_as_string_lit(&e);
            (e, lit)
        }
        None => {
            let auto = auto_custom_id_for(method);
            (parse_quote!(#auto), Some(auto))
        }
    };

    if matches!(method.sig.output, ReturnType::Default) {
        return Err(syn::Error::new_spanned(
            &method.sig,
            "#[modal] methods must return `InteractionResponse`",
        ));
    }

    let mut fields: Vec<ModalField> = Vec::new();
    for input in &method.sig.inputs {
        let FnArg::Typed(pt) = input else { continue };
        let has_field = pt.attrs.iter().any(|a| a.path().is_ident("field"));
        if !has_field {
            return Err(syn::Error::new_spanned(
                pt,
                "every parameter of a #[modal] method (other than `&self`) must be \
                 tagged with `#[field]`",
            ));
        }
        let ident = match &*pt.pat {
            Pat::Ident(p) => p.ident.clone(),
            _ => {
                return Err(syn::Error::new_spanned(
                    &pt.pat,
                    "#[modal] parameters must be plain `name: Type` bindings (no patterns)",
                ));
            }
        };
        let ty = &pt.ty;
        fields.push(ModalField {
            ident,
            extract_ty: quote!(#ty),
        });
    }

    // Reject duplicate field idents.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &fields {
        if !seen.insert(f.ident.to_string()) {
            return Err(syn::Error::new_spanned(
                &f.ident,
                format!("duplicate modal field `{}`", f.ident),
            ));
        }
    }

    Ok(ModalHandler {
        method_ident: method.sig.ident.clone(),
        custom_id_expr,
        literal_custom_id,
        fields,
    })
}

/// Placeholder auto-id assigned at parse time.  The surrounding type
/// name isn't yet known when `parse_component` / `parse_modal` runs,
/// so we tag the id with the `__auto::` prefix and let
/// [`finalize_auto_ids`] rewrite it into the canonical
/// `"<TypeName>::<method>"` form once `expand` has resolved the
/// `self_ty` ident.  This way both the constant in `__fancy_ids` and
/// the dispatch match arm see the same resolved string.
fn auto_custom_id_for(method: &ImplItemFn) -> String {
    format!("__auto::{}", method.sig.ident)
}

fn type_is_vec_string(ty: &Type) -> bool {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return false;
    };
    let Some(last) = path.segments.last() else {
        return false;
    };
    if last.ident != "Vec" {
        return false;
    }
    let PathArguments::AngleBracketed(ab) = &last.arguments else {
        return false;
    };
    let Some(GenericArgument::Type(inner)) = ab.args.first() else {
        return false;
    };
    let Type::Path(TypePath {
        qself: None,
        path: ip,
    }) = inner
    else {
        return false;
    };
    ip.segments
        .last()
        .map(|s| s.ident == "String")
        .unwrap_or(false)
}

fn extract_self_ty_ident(ty: &Type) -> syn::Result<Ident> {
    if let Type::Path(TypePath { qself: None, path }) = ty {
        if let Some(last) = path.segments.last() {
            return Ok(last.ident.clone());
        }
    }
    Err(syn::Error::new_spanned(
        ty,
        "#[fancy_plugin] requires a named `impl ... for <Type>` block",
    ))
}

/// Replace placeholder auto-ids on components and modals with the
/// resolved `"<TypeName>::<method>"` literal.  Also rejects duplicate
/// custom_ids within each kind (commands are deduped in `walk_impl`).
fn finalize_auto_ids(
    components: &mut [ComponentHandler],
    modals: &mut [ModalHandler],
    self_ty_ident: &Ident,
) -> syn::Result<()> {
    let type_name = self_ty_ident.to_string();

    for c in components.iter_mut() {
        if let Some(s) = &c.literal_custom_id {
            if let Some(method_name) = s.strip_prefix("__auto::") {
                let resolved = format!("{type_name}::{method_name}");
                c.custom_id_expr = parse_quote!(#resolved);
                c.literal_custom_id = Some(resolved);
            }
        }
    }
    for m in modals.iter_mut() {
        if let Some(s) = &m.literal_custom_id {
            if let Some(method_name) = s.strip_prefix("__auto::") {
                let resolved = format!("{type_name}::{method_name}");
                m.custom_id_expr = parse_quote!(#resolved);
                m.literal_custom_id = Some(resolved);
            }
        }
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in components.iter() {
        if let Some(id) = &c.literal_custom_id {
            if !seen.insert(id.clone()) {
                return Err(syn::Error::new_spanned(
                    &c.method_ident,
                    format!("duplicate component custom_id `{id}`"),
                ));
            }
        }
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in modals.iter() {
        if let Some(id) = &m.literal_custom_id {
            if !seen.insert(id.clone()) {
                return Err(syn::Error::new_spanned(
                    &m.method_ident,
                    format!("duplicate modal custom_id `{id}`"),
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// __fancy_ids module
// ---------------------------------------------------------------------------

/// Emit the `__fancy_ids` sub-module inside the inherent impl,
/// exposing per-handler wire-id constants:
///
/// * `pub const __FANCY_ID__<method>: &str = <wire id>;` for every
///   `#[command]`, `#[component]`, and `#[modal]` handler.
/// * `pub const __FANCY_FIELD__<method>__<field>: &str = "<field>";`
///   for every `#[modal]` handler's `#[field]` parameter.
///
/// These constants live on the inherent impl of the plugin type
/// because Rust forbids modules inside `impl` blocks.  They are
/// referenced by the [`mumble_plugin_api::handler_id!`] and
/// [`mumble_plugin_api::show_modal!`] proc-macros, which mangle
/// `<TypePath>::<method>` into `<TypePath>::__FANCY_ID__<method>`
/// and `<TypePath>::__FANCY_FIELD__<method>__<field>` so that the
/// builder and dispatcher sides agree on every wire identifier.
fn build_id_consts(
    commands: &[Command],
    components: &[ComponentHandler],
    modals: &[ModalHandler],
) -> TokenStream {
    let command_consts = commands.iter().map(|c| {
        let const_ident = format_ident!("__FANCY_ID__{}", c.method_ident);
        let name_expr = &c.name_expr;
        quote! {
            #[doc(hidden)]
            #[allow(non_upper_case_globals, reason = "method-name mangled")]
            pub const #const_ident: &::std::primitive::str = #name_expr;
        }
    });

    let component_consts = components.iter().map(|c| {
        let const_ident = format_ident!("__FANCY_ID__{}", c.method_ident);
        let id_expr = &c.custom_id_expr;
        quote! {
            #[doc(hidden)]
            #[allow(non_upper_case_globals, reason = "method-name mangled")]
            pub const #const_ident: &::std::primitive::str = #id_expr;
        }
    });

    let modal_consts = modals.iter().flat_map(|m| {
        let method = &m.method_ident;
        let id_const_ident = format_ident!("__FANCY_ID__{}", method);
        let id_expr = &m.custom_id_expr;
        let id_const = quote! {
            #[doc(hidden)]
            #[allow(non_upper_case_globals, reason = "method-name mangled")]
            pub const #id_const_ident: &::std::primitive::str = #id_expr;
        };
        let field_consts = m.fields.iter().map(move |f| {
            let field_const_ident = format_ident!("__FANCY_FIELD__{}__{}", method, f.ident);
            let fname = f.ident.to_string();
            quote! {
                #[doc(hidden)]
                #[allow(non_upper_case_globals, reason = "method/field-name mangled")]
                pub const #field_const_ident: &::std::primitive::str = #fname;
            }
        });
        std::iter::once(id_const).chain(field_consts)
    });

    quote! {
        #( #command_consts )*
        #( #component_consts )*
        #( #modal_consts )*
    }
}
