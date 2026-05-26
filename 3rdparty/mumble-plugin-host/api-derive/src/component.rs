//! `#[component]` attribute implementation.
//!
//! Acts mainly as a marker: the heavy lifting (custom-id constant,
//! dispatch wiring) happens in [`crate::fancy_plugin`] when it walks
//! the surrounding `impl` block.  This pass validates the
//! attribute's arguments so a user who forgets `#[fancy_plugin]`
//! still gets a clean error pointing at the right span.

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::parse2;

pub(crate) fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    // Validate args; #[fancy_plugin] reparses them when it walks the impl.
    let _ = ComponentArgs::parse(args)?;
    if let Ok(f) = parse2::<syn::ImplItemFn>(item.clone()) {
        return Ok(f.into_token_stream());
    }
    if let Ok(f) = parse2::<syn::ItemFn>(item.clone()) {
        return Ok(f.into_token_stream());
    }
    Err(syn::Error::new_spanned(
        &item,
        "#[component] must be applied to a function or method",
    ))
}

/// Parsed `#[component(custom_id = ...)]` arguments.
#[derive(Debug, Clone)]
pub(crate) struct ComponentArgs {
    /// Optional override for the auto-generated wire `custom_id`.
    /// When `None`, [`crate::fancy_plugin`] derives one from the
    /// surrounding type name and method name (e.g.
    /// `"MyPlugin::on_cancel"`).
    pub custom_id: Option<syn::Expr>,
}

impl ComponentArgs {
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
                Err(meta.error("unknown #[component] argument (accepted: custom_id)"))
            }
        });
        syn::parse::Parser::parse2(parser, tokens)?;
        Ok(Self { custom_id })
    }
}
