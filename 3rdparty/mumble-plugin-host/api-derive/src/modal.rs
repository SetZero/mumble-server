//! `#[modal]` and `#[field]` attribute implementations.
//!
//! The `#[modal]` attribute is a marker, like [`crate::command`] and
//! [`crate::component`]: the heavy lifting happens in
//! [`crate::fancy_plugin`].  This pass validates the attribute's
//! arguments and strips `#[field(...)]` attributes off parameters so
//! the function compiles in isolation when `#[fancy_plugin]` is
//! added incrementally.

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{parse2, FnArg, ImplItemFn, ItemFn};

pub(crate) fn modal_expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let _ = ModalArgs::parse(args)?;
    if let Ok(mut f) = parse2::<ImplItemFn>(item.clone()) {
        strip_field_attrs(&mut f.sig.inputs);
        return Ok(f.into_token_stream());
    }
    if let Ok(mut f) = parse2::<ItemFn>(item.clone()) {
        strip_field_attrs(&mut f.sig.inputs);
        return Ok(f.into_token_stream());
    }
    Err(syn::Error::new_spanned(
        &item,
        "#[modal] must be applied to a function or method",
    ))
}

/// `#[field]` is a per-parameter marker consumed by `#[modal]`'s
/// walker; on its own it accepts no arguments and emits the
/// underlying function unchanged.  It only exists so plugin authors
/// can write `#[field] message: String` without rustc rejecting it
/// as an unknown attribute when the surrounding `#[fancy_plugin]`
/// hasn't been added yet.
pub(crate) fn field_expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    if !args.is_empty() {
        return Err(syn::Error::new_spanned(
            &args,
            "#[field] takes no arguments",
        ));
    }
    Ok(item)
}

fn strip_field_attrs(inputs: &mut syn::punctuated::Punctuated<FnArg, syn::Token![,]>) {
    for arg in inputs.iter_mut() {
        if let FnArg::Typed(pt) = arg {
            pt.attrs
                .retain(|a| !a.path().is_ident("field") && !a.path().is_ident("doc"));
        }
    }
}

/// Parsed `#[modal(custom_id = ...)]` arguments.
#[derive(Debug, Clone)]
pub(crate) struct ModalArgs {
    /// Optional override for the auto-generated wire `custom_id`.
    pub custom_id: Option<syn::Expr>,
}

impl ModalArgs {
    pub(crate) fn parse(tokens: TokenStream) -> syn::Result<Self> {
        let mut custom_id: Option<syn::Expr> = None;
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("custom_id") {
                let value: syn::Expr = meta.value()?.parse()?;
                if custom_id.is_some() {
                    return Err(meta.error("duplicate `custom_id` argument"));
                }
                custom_id = Some(value);
                Ok(())
            } else {
                Err(meta.error("unknown #[modal] argument (accepted: custom_id)"))
            }
        });
        syn::parse::Parser::parse2(parser, tokens)?;
        Ok(Self { custom_id })
    }
}
