//! SSRF protection + the shared HTTP client.
//!
//! Ports `LinkPreviewPlugin`'s `isSafeUrl` / `isBlockedIp` /
//! `isPrivateAddress` / `resolveAndCheck` (the C++ used `QHostAddress` +
//! `QHostInfo`). The authoritative defence is a custom [`reqwest`] DNS resolver
//! ([`SsrfResolver`]) that resolves every host and refuses to hand back any
//! address in a blocked range - this rejects a public name whose A/AAAA record
//! points at an internal host, *and* re-runs on every redirect hop's connect,
//! closing DNS-rebinding. A cheap [`is_safe_url`] pre-filter rejects non-HTTP
//! schemes and literal private IPs before a request is even issued.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ip_network::{Ipv4Network, Ipv6Network};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::Url;

/// User-Agent sent on every preview fetch (mirrors the C++ value).
const USER_AGENT: &str = "Mozilla/5.0 (compatible; FancyMumbleBot/1.0)";
/// Maximum redirect hops to follow (mirrors `LinkPreviewPlugin::MAX_REDIRECTS`).
const MAX_REDIRECTS: usize = 5;

/// True when `ip` is not a globally-routable public address, i.e. anything we
/// refuse to connect to (private, loopback, link-local, CGNAT/shared,
/// documentation, reserved, ...). Classification is delegated to
/// [`ip_network`]'s `is_global`; we only normalise IPv4-mapped/compat IPv6 down
/// to the embedded IPv4 first, since the crate classifies those by their v6
/// form and an attacker could otherwise smuggle `::ffff:127.0.0.1` past it.
#[must_use]
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    // `is_global` treats some multicast as globally scoped; for SSRF we refuse
    // multicast and unspecified outright.
    if ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => !Ipv4Network::from(v4).is_global(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return !Ipv4Network::from(v4).is_global();
            }
            !Ipv6Network::from(v6).is_global()
        }
    }
}

/// True when `host` (a literal IP or a host name) is known to be
/// private/internal without DNS resolution. Host-name checks are a best-effort
/// fast path; the authoritative resolution check lives in [`SsrfResolver`].
#[must_use]
pub fn is_private_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    let h = host.to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
}

/// Cheap synchronous pre-filter: http(s) scheme, non-empty host, not an
/// obviously-private host. Mirrors `LinkPreviewPlugin::isSafeUrl`.
#[must_use]
pub fn is_safe_url(url: &Url) -> bool {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    match url.host_str() {
        Some(host) if !host.is_empty() => !is_private_host(host),
        _ => false,
    }
}

/// Replace the handful of HTML entities the C++ `decodeHtmlEntities` handled.
#[must_use]
pub fn decode_html_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Custom DNS resolver that resolves a host and rejects the lookup outright if
/// *any* returned address is in a blocked range. Wired into the shared client
/// so it runs for the initial request and every redirect hop.
#[derive(Debug, Default)]
struct SsrfResolver;

impl Resolve for SsrfResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let resolved = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let addrs: Vec<SocketAddr> = resolved.collect();
            if addrs.is_empty() {
                return Err("ssrf: host did not resolve to any address".into());
            }
            for sa in &addrs {
                if is_blocked_ip(sa.ip()) {
                    return Err("ssrf: host resolved to a blocked address".into());
                }
            }
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Build the shared HTTP client: SSRF resolver, redirect policy that
/// re-validates every hop's scheme/host, a total request timeout, and the
/// preview bot User-Agent.
#[must_use]
pub fn build_http_client(timeout: Duration) -> reqwest::Client {
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("ssrf: too many redirects");
        }
        if is_safe_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });

    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(timeout)
        .redirect(redirect)
        .dns_resolver(std::sync::Arc::new(SsrfResolver))
        .build()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn blocks_ipv4_private_and_special() {
        for s in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.168.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(is_blocked_ip(ip(s)), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for s in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "172.32.0.1"] {
            assert!(!is_blocked_ip(ip(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn blocks_ipv6_special_and_mapped() {
        for s in ["::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "::ffff:127.0.0.1"] {
            assert!(is_blocked_ip(ip(s)), "{s} should be blocked");
        }
        assert!(!is_blocked_ip(ip("2606:4700:4700::1111")), "public v6 allowed");
    }

    #[test]
    fn url_safety() {
        assert!(is_safe_url(&Url::parse("https://example.com/page").unwrap()));
        assert!(!is_safe_url(&Url::parse("http://localhost/x").unwrap()));
        assert!(!is_safe_url(&Url::parse("https://127.0.0.1/x").unwrap()));
        assert!(!is_safe_url(&Url::parse("ftp://example.com/x").unwrap()));
        assert!(!is_safe_url(&Url::parse("https://foo.internal/x").unwrap()));
    }

    #[test]
    fn entities() {
        assert_eq!(decode_html_entities("a &amp; b &lt;c&gt; &quot;d&quot; &#39;e&apos;"),
                   "a & b <c> \"d\" 'e'");
    }
}
