//! `#[command]` attribute implementation.
//!
//! Acts mainly as a marker: the heavy lifting (per-command descriptor,
//! invoker shim, dispatch wiring) happens in [`crate::fancy_plugin`]
//! when it walks the surrounding `impl` block.  This pass validates
//! the attribute's arguments so a user who forgets `#[fancy_plugin]`
//! still gets a clean error pointing at the right span.

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{parse2, FnArg, ImplItemFn, ItemFn};

pub(crate) fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    // Validate args; discard the parsed values - `#[fancy_plugin]`
    // reparses them when it walks the impl block.
    let _ = CommandArgs::parse(args)?;

    // Strip `#[option(...)]` attributes from parameters before
    // returning so rustc doesn't reject them as unknown attributes
    // when `#[command]` is used in isolation (e.g. when the
    // surrounding `#[fancy_plugin]` is being added incrementally).
    // The attributes' values are read out again by `#[fancy_plugin]`'s
    // parameter walker - which sees them BEFORE this proc-macro runs,
    // because attribute proc-macros are evaluated outside-in.
    //
    // Functions in impl blocks parse as `ImplItemFn`; standalone
    // functions parse as `ItemFn`.  Try both.
    if let Ok(mut f) = parse2::<ImplItemFn>(item.clone()) {
        strip_option_attrs(&mut f.sig.inputs);
        return Ok(f.into_token_stream());
    }
    if let Ok(mut f) = parse2::<ItemFn>(item.clone()) {
        strip_option_attrs(&mut f.sig.inputs);
        return Ok(f.into_token_stream());
    }
    Err(syn::Error::new_spanned(
        &item,
        "#[command] must be applied to a function or method",
    ))
}

fn strip_option_attrs(inputs: &mut syn::punctuated::Punctuated<FnArg, syn::Token![,]>) {
    for arg in inputs.iter_mut() {
        if let FnArg::Typed(pt) = arg {
            pt.attrs
                .retain(|a| !a.path().is_ident("option") && !a.path().is_ident("doc"));
        }
    }
}

/// Parsed `#[command(name = ..., description = ...)]` arguments.
#[derive(Debug, Clone)]
pub(crate) struct CommandArgs {
    /// Expression that evaluates to the slash-command name.  Required.
    pub name: syn::Expr,
    /// Optional override for the description; if absent the
    /// function's doc-comment is used instead.
    pub description: Option<syn::Expr>,
}

impl CommandArgs {
    pub(crate) fn parse(tokens: TokenStream) -> syn::Result<Self> {
        let mut name: Option<syn::Expr> = None;
        let mut description: Option<syn::Expr> = None;
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("name") {
                let value: syn::Expr = meta.value()?.parse()?;
                if name.is_some() {
                    return Err(meta.error("duplicate `name` argument"));
                }
                name = Some(value);
                Ok(())
            } else if meta.path.is_ident("description") {
                let value: syn::Expr = meta.value()?.parse()?;
                if description.is_some() {
                    return Err(meta.error("duplicate `description` argument"));
                }
                description = Some(value);
                Ok(())
            } else {
                Err(meta.error("unknown #[command] argument (accepted: name, description)"))
            }
        });
        syn::parse::Parser::parse2(parser, tokens)?;
        let Some(name) = name else {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "#[command] requires a `name` argument (e.g. `#[command(name = \"greet\")]`)",
            ));
        };
        Ok(Self { name, description })
    }
}
