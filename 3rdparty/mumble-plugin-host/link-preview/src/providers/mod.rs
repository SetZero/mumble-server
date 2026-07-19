//! Preview providers. Each inspects a URL and, if it can handle it, fetches and
//! returns an [`crate::embed::Embed`]. The manager runs them in priority order
//! (oEmbed and direct-media first, `OpenGraph` last as the generic fallback).

pub mod direct_media;
pub mod oembed;
pub mod opengraph;
