use super::{header, WebResponse};
use anyhow::{anyhow, ensure, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tiny_http::Header;

pub(super) fn loopback(value: &str) -> Result<SocketAddr> {
    let address = match value.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            let (host, port) = value
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("provide a loopback address and port"))?;
            ensure!(
                host.eq_ignore_ascii_case("localhost"),
                "Camio serves on loopback addresses only"
            );
            SocketAddr::from((Ipv4Addr::LOCALHOST, port.parse::<u16>()?))
        }
    };
    ensure!(
        address.ip().is_loopback(),
        "Camio serves on loopback addresses only"
    );
    Ok(address)
}

pub(super) struct LocalAccess {
    authority: String,
    origin: String,
    token: String,
}

impl LocalAccess {
    pub(super) fn new(socket: SocketAddr) -> Result<Self> {
        let authority = socket.to_string();
        let origin = format!("http://{authority}");
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|error| anyhow!("creating local session: {error}"))?;
        // Hex per byte via `format!` (the same idiom as the OAST token): writing to a
        // `String` cannot fail, but proving that to a reader costs more than not
        // asking it to handle a `Result`.
        let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            authority,
            origin,
            token,
        })
    }

    pub(super) fn open_url(&self) -> String {
        format!("{}/#session={}", self.origin, self.token)
    }

    pub(super) fn same_origin(&self, headers: &[Header]) -> bool {
        let Ok(Some(host)) = single_header(headers, "Host") else {
            return false;
        };
        // A browser omits the default HTTP port from Host and Origin.
        let host = if self.authority.ends_with(":80") {
            host.strip_suffix(":80").unwrap_or(host)
        } else {
            host
        };
        let expected = self
            .authority
            .strip_suffix(":80")
            .unwrap_or(&self.authority);
        // Hostnames are case-insensitive; compare normalized so `LOCALHOST:8787`
        // is not a confusing rejection.
        if !host.eq_ignore_ascii_case(expected) {
            return false;
        }
        let origin = self.origin.strip_suffix(":80").unwrap_or(&self.origin);
        let origin_matches = match single_header(headers, "Origin") {
            Ok(Some(value)) => value.eq_ignore_ascii_case(origin),
            Ok(None) => true,
            Err(()) => false,
        };
        origin_matches
            && matches!(
                single_header(headers, "Sec-Fetch-Site"),
                Ok(None | Some("same-origin" | "none"))
            )
    }

    pub(super) fn authorized(&self, headers: &[Header]) -> bool {
        let Ok(Some(value)) = single_header(headers, "Authorization") else {
            return false;
        };
        // The auth scheme is case-insensitive (RFC 7235): `bearer <token>` is
        // the same credentials as `Bearer <token>`.
        let Some((scheme, key)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return false;
        }
        key.len() == self.token.len()
            && key
                .bytes()
                .zip(self.token.bytes())
                .fold(0, |difference, (a, b)| difference | (a ^ b))
                == 0
    }
}

pub(super) fn single_header<'a>(
    headers: &'a [Header],
    name: &'static str,
) -> Result<Option<&'a str>, ()> {
    let mut values = headers.iter().filter(|header| header.field.equiv(name));
    let first = values.next().map(|header| header.value.as_str());
    if values.next().is_some() {
        Err(())
    } else {
        Ok(first)
    }
}

/// The security headers every response carries. All are constants, so a value
/// that fails validation is a programming error — and the answer is to drop
/// that one header, never to panic on a request path.
const SECURE_HEADERS: &[(&str, &str)] = &[
    ("Cache-Control", "no-store"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
         img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'",
    ),
];

pub(super) fn secure_headers(mut response: WebResponse) -> WebResponse {
    for (name, value) in SECURE_HEADERS {
        if let Some(h) = header(name, value) {
            response = response.with_header(h);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_requires_the_loopback_authority_and_key() {
        assert!(loopback("0.0.0.0:8787").is_err());
        assert!(loopback("localhost:8787").unwrap().ip().is_loopback());
        let access = LocalAccess::new("127.0.0.1:8787".parse().unwrap()).unwrap();
        let rebound = header("Host", "rebound.test:8787").expect("valid test header");
        assert!(!access.same_origin(&[rebound]));
        let host = header("Host", "127.0.0.1:8787").expect("valid test header");
        assert!(access.same_origin(std::slice::from_ref(&host)));
        assert!(!access.authorized(std::slice::from_ref(&host)));
        assert!(!access.same_origin(&[
            host.clone(),
            header("Origin", "http://other.test").expect("valid test header")
        ]));
        assert!(!access.same_origin(&[host.clone(), host.clone()]));
        let auth = header("Authorization", &format!("Bearer {}", access.token))
            .expect("valid test header");
        assert!(access.authorized(std::slice::from_ref(&auth)));
        // The scheme is case-insensitive per RFC 7235.
        let lower = header("Authorization", &format!("bearer {}", access.token)).expect("valid");
        assert!(access.authorized(std::slice::from_ref(&lower)));
        // A wrong key is still refused under either spelling.
        let wrong = header("Authorization", "bearer deadbeef").expect("valid");
        assert!(!access.authorized(std::slice::from_ref(&wrong)));
        // Host is case-insensitive, but a different host is still refused.
        let upper_host = header("Host", "127.0.0.1:8787").expect("valid");
        assert!(access.same_origin(std::slice::from_ref(&upper_host)));
        assert!(access.same_origin(&[
            upper_host.clone(),
            header("Origin", "http://127.0.0.1:8787").expect("valid"),
            header("Sec-Fetch-Site", "same-origin").expect("valid"),
        ]));
        assert!(access.same_origin(&[
            host,
            auth,
            header("Sec-Fetch-Site", "same-origin").expect("valid"),
        ]));
    }
}
