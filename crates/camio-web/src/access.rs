use super::{header, WebResponse};
use anyhow::{anyhow, ensure, Result};
use std::fmt::Write;
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
        let mut token = String::with_capacity(64);
        for byte in random {
            write!(token, "{byte:02x}").expect("writing to a String");
        }
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
        if host != expected {
            return false;
        }
        let origin = self.origin.strip_suffix(":80").unwrap_or(&self.origin);
        let origin_matches = match single_header(headers, "Origin") {
            Ok(Some(value)) => value == origin,
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
        let Some(key) = value.strip_prefix("Bearer ") else {
            return false;
        };
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

pub(super) fn secure_headers(response: WebResponse) -> WebResponse {
    response
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("Referrer-Policy", "no-referrer"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("X-Frame-Options", "DENY"))
        .with_header(header("Cross-Origin-Resource-Policy", "same-origin"))
        .with_header(header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_requires_the_loopback_authority_and_key() {
        assert!(loopback("0.0.0.0:8787").is_err());
        assert!(loopback("localhost:8787").unwrap().ip().is_loopback());
        let access = LocalAccess::new("127.0.0.1:8787".parse().unwrap()).unwrap();
        assert!(!access.same_origin(&[header("Host", "rebound.test:8787")]));
        let host = header("Host", "127.0.0.1:8787");
        assert!(access.same_origin(std::slice::from_ref(&host)));
        assert!(!access.authorized(std::slice::from_ref(&host)));
        assert!(!access.same_origin(&[host.clone(), header("Origin", "http://other.test")]));
        assert!(!access.same_origin(&[host.clone(), host.clone()]));
        let auth = header("Authorization", &format!("Bearer {}", access.token));
        assert!(access.authorized(std::slice::from_ref(&auth)));
        assert!(access.same_origin(&[host, auth, header("Sec-Fetch-Site", "same-origin")]));
    }
}
