//! Function-like proc-macros that bridge user-written `<Path>::<method>`
//! syntax to the per-handler associated consts emitted by
//! `#[fancy_plugin]` on the inherent impl of the plugin type.
//!
//! Rust forbids modules inside `impl` blocks, so the auto-generated
//! ids live on the impl as `pub const __FANCY_ID__<method>` /
//! `pub const __FANCY_FIELD__<method>__<field>` items.  These
//! macros do the (otherwise unwriteable in `macro_rules!`)
//! identifier-mangling that fuses the user-visible method ident
//! with the `__FANCY_ID__`/`__FANCY_FIELD__` prefix.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Expr, Ident, Path, PathSegment, Token,
};

/// `handler_id!(<Path>::<method>)` → `<Path>::__FANCY_ID__<method>`.
pub(crate) fn handler_id_expand(input: TokenStream) -> syn::Result<TokenStream> {
    let path: Path = syn::parse2(input)?;
    let (prefix, last) = split_path_tail(&path)?;
    let mangled = format_ident!("__FANCY_ID__{}", last, span = last.span());
    Ok(quote_spanned! { last.span() => #prefix #mangled })
}

/// `show_modal!(<Path>::<method>, <title>, { field: builder, ... })`
/// expands to a `ShowModal` `InteractionResponse` referencing the
/// `__FANCY_ID__<method>` and `__FANCY_FIELD__<method>__<field>`
/// associated consts emitted by `#[fancy_plugin]`.
pub(crate) fn show_modal_expand(input: TokenStream) -> syn::Result<TokenStream> {
    let parsed: ShowModalInput = syn::parse2(input)?;
    let path = parsed.path;
    let (prefix, last) = split_path_tail(&path)?;
    let id_const = format_ident!("__FANCY_ID__{}", last, span = last.span());
    let title = parsed.title;

    let field_pushes = parsed.fields.into_iter().map(|f| {
        let field_const = format_ident!(
            "__FANCY_FIELD__{}__{}",
            last,
            f.ident,
            span = f.ident.span()
        );
        let builder = f.builder;
        let prefix = prefix.clone();
        quote_spanned! { f.ident.span() =>
            __r = __r.field(
                ::mumble_plugin_api::__text_input_with_id(
                    #prefix #field_const,
                    #builder,
                ),
            );
        }
    });

    Ok(quote! {{
        #[allow(unused_mut, reason = "macro-generated when no fields are given")]
        let mut __r = ::mumble_plugin_api::InteractionResponse::show_modal(
            #prefix #id_const,
            #title,
        );
        #( #field_pushes )*
        __r
    }})
}

/// Split `A::B::C::method` into (`A::B::C::`, `method`).
/// The returned prefix already contains the trailing `::`, so callers
/// can splice the mangled tail with `#prefix #mangled`.
fn split_path_tail(path: &Path) -> syn::Result<(TokenStream, Ident)> {
    let Some(last_seg) = path.segments.last() else {
        return Err(syn::Error::new_spanned(
            path,
            "expected `<Path>::<method>` with at least one segment",
        ));
    };
    if !last_seg.arguments.is_none() {
        return Err(syn::Error::new_spanned(
            &last_seg.arguments,
            "handler path tail must be a bare ident, not a generic instantiation",
        ));
    }
    let last = last_seg.ident.clone();

    let prefix_segments: Vec<&PathSegment> = path
        .segments
        .iter()
        .take(path.segments.len().saturating_sub(1))
        .collect();
    let leading_colon = path.leading_colon;
    let prefix = if prefix_segments.is_empty() {
        // Bare method name — no prefix.  The mangled ident resolves
        // against the surrounding scope just like the user-written
        // ident would have.
        quote! {}
    } else {
        quote! { #leading_colon #( #prefix_segments )::* :: }
    };
    Ok((prefix, last))
}

struct ShowModalInput {
    path: Path,
    title: Expr,
    fields: Punctuated<ShowModalField, Token![,]>,
}

struct ShowModalField {
    ident: Ident,
    builder: Expr,
}

impl Parse for ShowModalInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path: Path = input.parse()?;
        let _: Token![,] = input.parse()?;
        let title: Expr = input.parse()?;
        let _: Token![,] = input.parse()?;
        let braced;
        syn::braced!(braced in input);
        let fields = braced.parse_terminated(ShowModalField::parse, Token![,])?;
        // Optional trailing comma after the brace block is consumed
        // by the brace itself; nothing else may follow.
        if !input.is_empty() {
            let _ = input.parse::<Token![,]>().ok();
            if !input.is_empty() {
                return Err(input.error("unexpected tokens after `show_modal!` field block"));
            }
        }
        Ok(Self {
            path,
            title,
            fields,
        })
    }
}

impl Parse for ShowModalField {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: Ident = input.parse()?;
        let _: Token![:] = input.parse()?;
        let builder: Expr = input.parse()?;
        Ok(Self { ident, builder })
    }
}
