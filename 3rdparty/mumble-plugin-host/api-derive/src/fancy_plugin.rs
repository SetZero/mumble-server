//! `#[fancy_plugin]` attribute implementation.
//!
//! Walks an **inherent** `impl X { ... }` block (no trait keyword) and:
//!
//! * Extracts the impl-position `plugin_info! { ... }` invocation
//!   tokens and reuses them inside a synthesised `fn info_json`.
//! * Collects `#[command]`-tagged methods, building per-method
//!   slash-command manifest entries and an inherent dispatch table.
//! * Collects lifecycle methods written by the user
//!   (`on_load`, `on_unload`, `on_client_connected`,
//!   `on_client_disconnected`, `on_plugin_data`, `on_plugin_message`),
//!   each of which takes `host: Host<'_>` as its first parameter
//!   after `&self`.
//! * Generates a complete `impl MumblePlugin for X` block: every
//!   lifecycle wrapper constructs `Host::new(ctx, name)` and calls
//!   into the user's inherent method; users never see the raw
//!   `PluginContext_TO`.
//! * Emits a sibling inherent impl with the auto-generated
//!   `__fancy_auto_slash_commands` and `__fancy_dispatch` helpers.
//!
//! Plugin authors no longer store any plugin context themselves; the
//! host crate owns the `PluginContext_TO` and passes it into every
//! callback.
//!
//! ```ignore
//! #[fancy_plugin(name = "my-plugin", version = env!("CARGO_PKG_VERSION"))]
//! impl MyPlugin {
//!     plugin_info! { description: "...", ... }
//!
//!     fn on_load(&self, host: Host<'_>) -> PluginResult<()> {
//!         // use host.get_config(...), host.send_plugin_message(...), ...
//!         ROk(())
//!     }
//!
//!     #[command(name = "ping")]
//!     fn ping(&self, host: Host<'_>) -> InteractionResponse { /* ... */ }
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

    // The macro now generates the `impl MumblePlugin for X` block
    // itself, so the input must be an *inherent* impl.  Refusing the
    // legacy `impl MumblePlugin for X { ... }` shape early gives a
    // clearer migration error than the trait-impl method conflicts
    // that would otherwise surface.
    if let Some((_, ref path, _)) = input.trait_ {
        return Err(syn::Error::new_spanned(
            path,
            "#[fancy_plugin] now wraps an *inherent* `impl YourPlugin { ... }` block; \
             remove the `MumblePlugin for` part - the trait impl is generated for you",
        ));
    }

    // Pull the self-type ident so we can attach an inherent impl with
    // the right path even when there are generic parameters.
    let self_ty = input.self_ty.clone();

    let Walked {
        plugin_info_tokens,
        commands,
        mut components,
        mut modals,
        lifecycle,
        kept_items,
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
    let lifecycle_fns = build_lifecycle_fns(&lifecycle, name_expr);
    let on_msg_fn = build_on_plugin_message_fn(lifecycle.on_plugin_message, name_expr);
    let auto_cmds_fn = build_auto_slash_commands_fn(&commands);
    let dispatch_fn = build_dispatch_fn(&commands, &components, &modals);
    let id_consts = build_id_consts(&commands, &components, &modals);
    let no_desc_warnings = build_no_description_warnings(&commands, &self_ty);

    // The user's input becomes a plain inherent impl carrying every
    // item they wrote (handlers, lifecycle methods, helpers).  The
    // synthesised `impl MumblePlugin for X` and the dispatch helpers
    // live in separate sibling impls so the user's writeable surface
    // stays uncluttered.
    input.items = kept_items;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        #input

        #[allow(non_snake_case, reason = "macro-generated identifiers are namespaced with __fancy_")]
        const _: () = {
            #no_desc_warnings
        };

        impl #impl_generics ::mumble_plugin_api::MumblePlugin for #self_ty #ty_generics #where_clause {
            #name_fn
            #version_fn
            #info_json_fn
            #(#lifecycle_fns)*
            #on_msg_fn
        }

        impl #impl_generics #self_ty #ty_generics #where_clause {
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
    /// Lifecycle methods (`on_load`, `on_unload`, `on_client_connected`,
    /// `on_client_disconnected`, `on_plugin_data`, `on_plugin_message`)
    /// the user wrote.  Each entry records *whether* the user wrote
    /// the method (so the generated trait wrapper can call it) or
    /// *not* (so the trait wrapper uses a no-op default).  The
    /// methods themselves remain in [`Walked::kept_items`] as
    /// inherent methods.
    lifecycle: LifecyclePresence,
    /// Every other item from the user's inherent impl, in source
    /// order.  Includes lifecycle methods, command/component/modal
    /// handlers (with their attribute removed), `use` items, type
    /// aliases, plain helper methods, and so on.
    kept_items: Vec<ImplItem>,
}

#[derive(Default)]
struct LifecyclePresence {
    on_load: bool,
    on_unload: bool,
    on_client_connected: bool,
    on_client_disconnected: bool,
    on_plugin_data: bool,
    /// Whether the user wrote a `fn on_plugin_message`.  When `true`,
    /// the generated trait wrapper calls into the user's inherent
    /// method after the auto-dispatch pass fails to claim the
    /// envelope.  When `false`, the wrapper simply returns `ROk(())`.
    on_plugin_message: bool,
}

const LIFECYCLE_METHOD_NAMES: &[&str] = &[
    "on_load",
    "on_unload",
    "on_client_connected",
    "on_client_disconnected",
    "on_plugin_data",
    "on_plugin_message",
];

fn walk_impl(input: &mut ItemImpl) -> syn::Result<Walked> {
    let mut plugin_info_tokens: Option<TokenStream> = None;
    let mut commands: Vec<Command> = Vec::new();
    let mut components: Vec<ComponentHandler> = Vec::new();
    let mut modals: Vec<ModalHandler> = Vec::new();
    let mut lifecycle = LifecyclePresence::default();
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
            // lifecycle hook / forbidden override (name/version/
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
                    kept_items.push(ImplItem::Fn(f));
                } else if let Some(idx) = comp_idx {
                    let attr = f.attrs.remove(idx);
                    let comp = parse_component(&attr, &f)?;
                    strip_param_macro_attrs(&mut f);
                    components.push(comp);
                    kept_items.push(ImplItem::Fn(f));
                } else if let Some(idx) = modal_idx {
                    let attr = f.attrs.remove(idx);
                    let m = parse_modal(&attr, &f)?;
                    strip_param_macro_attrs(&mut f);
                    modals.push(m);
                    kept_items.push(ImplItem::Fn(f));
                } else if LIFECYCLE_METHOD_NAMES.contains(&ident.to_string().as_str()) {
                    // Lifecycle method: record presence (and for
                    // on_plugin_message, the original body so the
                    // dispatch prelude can be spliced in).  The
                    // method itself stays as an inherent method on
                    // the user's impl so the macro-generated trait
                    // wrapper can call `Self::on_load(self, host)`.
                    match ident.to_string().as_str() {
                        "on_load" => {
                            if lifecycle.on_load {
                                return Err(syn::Error::new_spanned(
                                    &f.sig.ident,
                                    "duplicate `fn on_load`",
                                ));
                            }
                            lifecycle.on_load = true;
                            kept_items.push(ImplItem::Fn(f));
                        }
                        "on_unload" => {
                            if lifecycle.on_unload {
                                return Err(syn::Error::new_spanned(
                                    &f.sig.ident,
                                    "duplicate `fn on_unload`",
                                ));
                            }
                            lifecycle.on_unload = true;
                            kept_items.push(ImplItem::Fn(f));
                        }
                        "on_client_connected" => {
                            if lifecycle.on_client_connected {
                                return Err(syn::Error::new_spanned(
                                    &f.sig.ident,
                                    "duplicate `fn on_client_connected`",
                                ));
                            }
                            lifecycle.on_client_connected = true;
                            kept_items.push(ImplItem::Fn(f));
                        }
                        "on_client_disconnected" => {
                            if lifecycle.on_client_disconnected {
                                return Err(syn::Error::new_spanned(
                                    &f.sig.ident,
                                    "duplicate `fn on_client_disconnected`",
                                ));
                            }
                            lifecycle.on_client_disconnected = true;
                            kept_items.push(ImplItem::Fn(f));
                        }
                        "on_plugin_data" => {
                            if lifecycle.on_plugin_data {
                                return Err(syn::Error::new_spanned(
                                    &f.sig.ident,
                                    "duplicate `fn on_plugin_data`",
                                ));
                            }
                            lifecycle.on_plugin_data = true;
                            kept_items.push(ImplItem::Fn(f));
                        }
                        "on_plugin_message" => {
                            if lifecycle.on_plugin_message {
                                return Err(syn::Error::new_spanned(
                                    &f.sig.ident,
                                    "duplicate `fn on_plugin_message`",
                                ));
                            }
                            lifecycle.on_plugin_message = true;
                            kept_items.push(ImplItem::Fn(f));
                        }
                        _ => unreachable!(),
                    }
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
        lifecycle,
        kept_items,
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
    /// `true` when the user declared `host: Host<'_>` as the first
    /// parameter after `&self`.  The dispatcher then injects the
    /// active `Host` for that position; the parameter is NOT added
    /// to the slash-command manifest.
    takes_host: bool,
    /// Typed parameters in declaration order (with any leading
    /// `host: Host<'_>` excluded).
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

    let typed: Vec<&syn::PatType> = method
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Receiver(_) => None,
            FnArg::Typed(pt) => Some(pt),
        })
        .collect();

    // A leading `host: Host<'_>` parameter is consumed by the
    // dispatcher and excluded from the slash-command manifest.
    let (takes_host, rest): (bool, &[&syn::PatType]) = match typed.split_first() {
        Some((first, tail)) if is_host_param_type(&first.ty) => (true, tail),
        _ => (false, typed.as_slice()),
    };
    // Host must come before the wire params; reject it anywhere else
    // to keep dispatcher injection straightforward and the error
    // message obvious.
    for pt in rest {
        if is_host_param_type(&pt.ty) {
            return Err(syn::Error::new_spanned(
                &pt.ty,
                "`host: Host<'_>` must be the first parameter after `&self`",
            ));
        }
    }
    let params = rest
        .iter()
        .copied()
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
        takes_host,
        params,
    })
}

/// Detect a `host: Host<'_>` parameter type.  Match the last
/// path-segment ident equal to `Host` so users can write either the
/// short form (`Host<'_>`, after `use ::mumble_plugin_api::Host`) or
/// any qualified form (`mumble_plugin_api::Host<'_>`).  The lifetime
/// argument is not checked - any lifetime/elided lifetime is accepted.
fn is_host_param_type(ty: &Type) -> bool {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return false;
    };
    path.segments
        .last()
        .map(|s| s.ident == "Host")
        .unwrap_or(false)
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

fn build_on_plugin_message_fn(user_provided: bool, name_expr: &Expr) -> ImplItemFn {
    // The dispatch prelude builds a `Host` over the borrowed context
    // and asks `__fancy_dispatch` to claim the envelope.  If a
    // `#[command]` / `#[component]` / `#[modal]` handler matched, the
    // generated response is shipped via `host.respond`.  Otherwise -
    // and only otherwise - control falls through to the user's
    // inherent `on_plugin_message` (when present), or to a no-op
    // default.
    let fallthrough = if user_provided {
        quote! {
            <Self>::on_plugin_message(self, __host, msg)
        }
    } else {
        quote! {
            ::abi_stable::std_types::RResult::ROk(())
        }
    };

    parse_quote! {
        fn on_plugin_message(
            &self,
            __ctx: &::mumble_plugin_api::PluginContext_TO<::abi_stable::std_types::RArc<()>>,
            msg: ::mumble_plugin_api::PluginMessageIn,
        ) -> ::mumble_plugin_api::PluginResult<()> {
            let __host = ::mumble_plugin_api::Host::new(__ctx, #name_expr);
            if let ::std::option::Option::Some(__response) = self.__fancy_dispatch(__host, &msg) {
                __host.respond(&msg, __response);
                return ::abi_stable::std_types::RResult::ROk(());
            }
            #fallthrough
        }
    }
}

/// Build the trait-impl wrappers for every lifecycle hook the user
/// provided.  Each wrapper translates the FFI signature
/// (`&PluginContext_TO<RArc<()>>` + payload) into the ergonomic
/// `Host<'_>` shape the user wrote against, then delegates to the
/// inherent method on `Self`.  Hooks the user didn't write are
/// omitted entirely so the trait's default no-op impl applies.
fn build_lifecycle_fns(presence: &LifecyclePresence, name_expr: &Expr) -> Vec<ImplItemFn> {
    let mut fns = Vec::new();
    if presence.on_load {
        fns.push(parse_quote! {
            fn on_load(
                &self,
                __ctx: ::mumble_plugin_api::PluginContext_TO<::abi_stable::std_types::RArc<()>>,
            ) -> ::mumble_plugin_api::PluginResult<()> {
                // The trait hands `on_load` an owned trait object so
                // plugins that need long-lived access can retain it.
                // Macro-driven plugins only see `Host<'_>`, so we
                // build a host facade over the borrowed handle and
                // drop the owned copy at the end of this scope.
                let __ctx_owned = __ctx;
                let __host = ::mumble_plugin_api::Host::new(&__ctx_owned, #name_expr);
                <Self>::on_load(self, __host)
            }
        });
    }
    if presence.on_unload {
        fns.push(parse_quote! {
            fn on_unload(
                &self,
                __ctx: &::mumble_plugin_api::PluginContext_TO<::abi_stable::std_types::RArc<()>>,
            ) -> ::mumble_plugin_api::PluginResult<()> {
                let __host = ::mumble_plugin_api::Host::new(__ctx, #name_expr);
                <Self>::on_unload(self, __host)
            }
        });
    }
    if presence.on_client_connected {
        fns.push(parse_quote! {
            fn on_client_connected(
                &self,
                __ctx: &::mumble_plugin_api::PluginContext_TO<::abi_stable::std_types::RArc<()>>,
                info: ::mumble_plugin_api::ClientInfo,
            ) -> ::mumble_plugin_api::PluginResult<()> {
                let __host = ::mumble_plugin_api::Host::new(__ctx, #name_expr);
                <Self>::on_client_connected(self, __host, info)
            }
        });
    }
    if presence.on_client_disconnected {
        fns.push(parse_quote! {
            fn on_client_disconnected(
                &self,
                __ctx: &::mumble_plugin_api::PluginContext_TO<::abi_stable::std_types::RArc<()>>,
                server_id: ::mumble_plugin_api::ServerId,
                session: ::mumble_plugin_api::SessionId,
            ) -> ::mumble_plugin_api::PluginResult<()> {
                let __host = ::mumble_plugin_api::Host::new(__ctx, #name_expr);
                <Self>::on_client_disconnected(self, __host, server_id, session)
            }
        });
    }
    if presence.on_plugin_data {
        fns.push(parse_quote! {
            fn on_plugin_data(
                &self,
                __ctx: &::mumble_plugin_api::PluginContext_TO<::abi_stable::std_types::RArc<()>>,
                server_id: ::mumble_plugin_api::ServerId,
                sender: ::mumble_plugin_api::SessionId,
                data_id: ::abi_stable::std_types::RStr<'_>,
                data: ::abi_stable::std_types::RSlice<'_, u8>,
            ) -> ::mumble_plugin_api::PluginResult<()> {
                let __host = ::mumble_plugin_api::Host::new(__ctx, #name_expr);
                <Self>::on_plugin_data(self, __host, server_id, sender, data_id, data)
            }
        });
    }
    fns
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
        let host_prefix = if c.takes_host {
            quote!(__host,)
        } else {
            TokenStream::new()
        };
        quote! {
            __name if __name == ::std::convert::AsRef::<str>::as_ref(#name_expr) => {
                #(#extractions)*
                let mut __resp = self.#method( #host_prefix #(#arg_idents),* );
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
        let host_prefix = if c.takes_host {
            quote!(__host,)
        } else {
            TokenStream::new()
        };
        let call = match c.values_binding {
            ComponentValuesBinding::None => quote! { self.#method( #host_prefix ) },
            ComponentValuesBinding::Values => quote! {
                self.#method(
                    #host_prefix
                    __values.iter().map(::std::string::ToString::to_string).collect::<::std::vec::Vec<::std::string::String>>(),
                )
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
        let host_prefix = if m.takes_host {
            quote!(__host,)
        } else {
            TokenStream::new()
        };
        quote! {
            __cid if __cid == ::std::convert::AsRef::<str>::as_ref(#id_expr) => {
                #(#extractions)*
                let mut __resp = self.#method( #host_prefix #(#arg_idents),* );
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
            __host: ::mumble_plugin_api::Host<'_>,
            __msg: &::mumble_plugin_api::PluginMessageIn,
        ) -> ::std::option::Option<::mumble_plugin_api::InteractionResponse> {
            // `__host` is always available for handlers; suppress the
            // unused warning when no handler claims it.
            let _ = __host;
            if __msg.payload_type.as_str() != ::mumble_plugin_api::INTERACTION_PAYLOAD_TYPE {
                return ::std::option::Option::None;
            }
            let __interaction = ::mumble_plugin_api::parse_interaction(__msg)?;
            let __correlation_id = __interaction.correlation_id.clone();
            let __correlation_id: &::std::primitive::str = __correlation_id.as_str();
            // Rebuild `__host` with caller context so handlers can
            // call `host.caller()` to find out who triggered them.
            let __host = ::mumble_plugin_api::Host::with_caller(
                __host.raw(),
                __host.plugin_name(),
                ::mumble_plugin_api::Caller::new(
                    __msg.server_id,
                    __msg.sender_session,
                    __interaction.channel_id,
                ),
            );
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
    /// `true` when the user declared `host: Host<'_>` as the first
    /// parameter after `&self` (the dispatcher injects the active
    /// `Host` and the parameter is excluded from any manifest).
    takes_host: bool,
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
    /// `true` when the user declared `host: Host<'_>` as the first
    /// parameter after `&self`.
    takes_host: bool,
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

    // Classify the non-self parameter list.  A leading `host:
    // Host<'_>` parameter is consumed by the dispatcher.  After
    // that, the handler accepts either zero parameters or a single
    // `Vec<String>` named `values`.
    let typed: Vec<&syn::PatType> = method
        .sig
        .inputs
        .iter()
        .filter_map(|i| match i {
            FnArg::Typed(pt) => Some(pt),
            FnArg::Receiver(_) => None,
        })
        .collect();
    let (takes_host, rest): (bool, &[&syn::PatType]) = match typed.split_first() {
        Some((first, tail)) if is_host_param_type(&first.ty) => (true, tail),
        _ => (false, typed.as_slice()),
    };
    for pt in rest {
        if is_host_param_type(&pt.ty) {
            return Err(syn::Error::new_spanned(
                &pt.ty,
                "`host: Host<'_>` must be the first parameter after `&self`",
            ));
        }
    }
    let values_binding = match rest {
        [] => ComponentValuesBinding::None,
        [pt] => {
            if !type_is_vec_string(&pt.ty) {
                return Err(syn::Error::new_spanned(
                    &pt.ty,
                    "#[component] methods accept an optional `host: Host<'_>` followed by \
                     either no parameters or a single `Vec<String>` parameter",
                ));
            }
            ComponentValuesBinding::Values
        }
        _ => {
            return Err(syn::Error::new_spanned(
                &method.sig.inputs,
                "#[component] methods accept an optional `host: Host<'_>` followed by \
                 either no parameters or a single `Vec<String>` parameter",
            ));
        }
    };

    Ok(ComponentHandler {
        method_ident: method.sig.ident.clone(),
        custom_id_expr,
        literal_custom_id,
        values_binding,
        takes_host,
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
    let mut takes_host = false;
    let mut saw_field = false;
    for input in &method.sig.inputs {
        let FnArg::Typed(pt) = input else { continue };
        // A leading `host: Host<'_>` is consumed by the dispatcher.
        // It must precede every `#[field]` param so injection is
        // positional and obvious.
        if is_host_param_type(&pt.ty) {
            if saw_field {
                return Err(syn::Error::new_spanned(
                    &pt.ty,
                    "`host: Host<'_>` must be the first parameter after `&self`",
                ));
            }
            if takes_host {
                return Err(syn::Error::new_spanned(
                    &pt.ty,
                    "duplicate `host: Host<'_>` parameter",
                ));
            }
            takes_host = true;
            continue;
        }
        let has_field = pt.attrs.iter().any(|a| a.path().is_ident("field"));
        if !has_field {
            return Err(syn::Error::new_spanned(
                pt,
                "every parameter of a #[modal] method (other than `&self` and an \
                 optional leading `host: Host<'_>`) must be tagged with `#[field]`",
            ));
        }
        saw_field = true;
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
        takes_host,
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
