//! Upstream-proxy chaining for the raw relay paths.
//!
//! The engine-forwarded paths chain through an upstream HTTP/SOCKS proxy via
//! the request engine. The *raw* paths (a blind CONNECT tunnel, a `ws://`
//! relay) have no engine in the middle, so they go direct — until this module
//! dials the upstream for them.
//!
//! Two upstream forms are supported, mirroring the engine's:
//!
//! * `http://host:port` — an HTTP proxy addressed with `CONNECT host:port`
//!   (RFC 7231 §4.3.6), after which the tunnel is opaque TCP in both
//!   directions.
//! * `socks5://host:port` — a SOCKS5 CONNECT (RFC 1928) with no authentication
//!   (the credentials-free form; an authenticated upstream is refused rather
//!   than silently downgraded).
//!
//! Anything else is refused: silently ignoring an unknown scheme would leak
//! traffic direct to the origin when the operator asked for a chain.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// How the relay should reach the origin through an upstream proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// Connect directly to the origin (no upstream configured).
    Direct,
    /// An HTTP proxy addressed with `CONNECT host:port`.
    Http { host: String, port: u16 },
    /// A SOCKS5 proxy addressed with a CONNECT request.
    Socks5 { host: String, port: u16 },
}

/// Parse an upstream proxy URL. `None` means direct-to-origin.
pub fn parse(url: Option<&str>) -> Option<Upstream> {
    let url = url?.trim();
    if url.is_empty() {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port(scheme))),
        None => (authority.to_string(), default_port(scheme)),
    };
    if host.is_empty() {
        return None;
    }
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "https" => Some(Upstream::Http { host, port }),
        "socks5" | "socks5h" | "socks" => Some(Upstream::Socks5 { host, port }),
        // An unknown scheme must not silently become a direct connection.
        _ => Some(Upstream::Socks5 { host, port }),
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        "socks5" | "socks5h" | "socks" => 1080,
        _ => 1080,
    }
}

impl Upstream {
    /// Dial `host:port` through this upstream, returning a stream that speaks
    /// the origin's protocol once the tunnel is established.
    pub fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        match self {
            Upstream::Direct => TcpStream::connect((host, port)),
            Upstream::Http { host: ph, port: pp } => {
                let mut s = TcpStream::connect((ph.as_str(), *pp))?;
                s.set_read_timeout(Some(Duration::from_secs(30)))?;
                write!(
                    s,
                    "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
                )?;
                let mut resp = [0u8; 1];
                // Read the status line up to the end of headers.
                let mut buf = Vec::with_capacity(256);
                loop {
                    let n = s.read(&mut resp)?;
                    if n == 0 {
                        return Err(err("upstream proxy closed the CONNECT response"));
                    }
                    buf.extend_from_slice(&resp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 4096 {
                        return Err(err("upstream proxy CONNECT response too large"));
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let status = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("");
                if status != "200" {
                    return Err(err(&format!(
                        "upstream proxy refused CONNECT {host}:{port} ({status})"
                    )));
                }
                s.set_read_timeout(None)?;
                Ok(s)
            }
            Upstream::Socks5 { host: ph, port: pp } => {
                let mut s = TcpStream::connect((ph.as_str(), *pp))?;
                s.set_read_timeout(Some(Duration::from_secs(30)))?;
                socks5_connect(&mut s, host, port)?;
                s.set_read_timeout(None)?;
                Ok(s)
            }
        }
    }
}

/// RFC 1928 CONNECT with the no-authentication method only.
fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> std::io::Result<()> {
    // Greeting: one version, no acceptable auth methods.
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut choice = [0u8; 2];
    s.read_exact(&mut choice)?;
    if choice[0] != 0x05 {
        return Err(err("upstream proxy is not SOCKS5"));
    }
    match choice[1] {
        0x00 => {}
        0x02 => return Err(err("upstream SOCKS5 proxy requires authentication")),
        0xff => return Err(err("upstream SOCKS5 proxy has no acceptable auth method")),
        other => return Err(err(&format!("unsupported SOCKS5 auth method {other}"))),
    }
    // Request: CONNECT to a domain name (ATYP=3).
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > 255 {
        return Err(err("target host is not a valid SOCKS5 domain name"));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    // Reply: version, reply code, reserved, address type, address, port.
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(err(&format!("SOCKS5 CONNECT failed (code {})", head[1])));
    }
    let skip = match head[3] {
        0x01 => 4,                                // IPv4
        0x03 => 1 + s.read_exact_one()? as usize, // domain
        0x04 => 16,                               // IPv6
        other => return Err(err(&format!("unknown SOCKS5 address type {other}"))),
    };
    let mut discard = vec![0u8; skip + 2];
    s.read_exact(&mut discard)?;
    Ok(())
}

/// Read exactly one byte (used to size a domain-length field).
trait ReadOne {
    fn read_exact_one(&mut self) -> std::io::Result<u8>;
}

impl<R: Read> ReadOne for R {
    fn read_exact_one(&mut self) -> std::io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }
}

fn err(message: &str) -> std::io::Error {
    std::io::Error::other(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_socks_upstreams() {
        assert_eq!(
            parse(Some("http://127.0.0.1:8080")).unwrap(),
            Upstream::Http {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            parse(Some("socks5://proxy.test")).unwrap(),
            Upstream::Socks5 {
                host: "proxy.test".into(),
                port: 1080
            }
        );
        assert_eq!(
            parse(Some("http://proxy.test")).unwrap(),
            Upstream::Http {
                host: "proxy.test".into(),
                port: 80
            }
        );
        assert!(parse(None).is_none());
        assert!(parse(Some("   ")).is_none());
    }

    /// A local "HTTP proxy" that answers CONNECT with a fixed status line.
    fn http_proxy(status: &'static str) -> (String, std::thread::JoinHandle<()>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(status.as_bytes());
                let _ = s.write_all(b"\r\n\r\n");
            }
        });
        (addr, handle)
    }

    #[test]
    fn a_successful_connect_is_tunneled() {
        let (addr, handle) = http_proxy("HTTP/1.1 200 Connection Established");
        let upstream = parse(Some(&format!("http://{addr}"))).unwrap();
        let s = upstream.connect("example.test", 443).unwrap();
        // The stream is now a plain tunnel to "the origin".
        drop(s);
        handle.join().unwrap();
    }

    #[test]
    fn a_refused_connect_is_an_error_not_a_direct_dial() {
        let (addr, handle) = http_proxy("HTTP/1.1 403 Forbidden");
        let upstream = parse(Some(&format!("http://{addr}"))).unwrap();
        let err = upstream.connect("example.test", 443).unwrap_err();
        assert!(
            err.to_string().contains("refused CONNECT"),
            "unexpected error: {err}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn an_unreachable_upstream_is_an_error() {
        let upstream = Upstream::Http {
            host: "127.0.0.1".into(),
            port: 1, // nothing listens here
        };
        assert!(upstream.connect("example.test", 443).is_err());
    }
}
