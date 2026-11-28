//! A minimal RFC 6455 WebSocket **client**, used to drive the WebDriver BiDi
//! session against the managed browser's remote agent (plan §5, F05).
//!
//! The protocol pieces — the opening-handshake `Sec-WebSocket-Accept`
//! computation, the handshake request, and client-masked frame encode / server
//! frame decode — are pure and unit-tested against the RFC 6455 vectors. Only
//! [`WebSocketBiDiTransport`]'s socket I/O (TCP connect, read/write) is the thin,
//! browser-dependent glue; it is built entirely on the tested codec below and
//! implements [`crate::bidi::BiDiTransport`], so the capture loop that drives it
//! is itself tested with a mock transport.

use crate::bidi::BiDiTransport;
use base64::Engine as _;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::io::{self, Read, Write};
use std::net::TcpStream;

/// The RFC 6455 GUID appended to the client key before hashing.
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute `Sec-WebSocket-Accept` from the client's `Sec-WebSocket-Key`.
pub fn accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.trim().as_bytes());
    hasher.update(WS_GUID);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Build the opening-handshake HTTP request for `path` on `host` with `key`.
pub fn handshake_request(host: &str, path: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    )
}

/// Validate a handshake response: a `101` status whose `Sec-WebSocket-Accept`
/// matches `accept_key(sent_key)`.
pub fn handshake_ok(response: &str, sent_key: &str) -> bool {
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 101") && !status.starts_with("HTTP/1.0 101") {
        return false;
    }
    let expected = accept_key(sent_key);
    lines.any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.trim().eq_ignore_ascii_case("sec-websocket-accept")
                    && value.trim() == expected
            })
            .unwrap_or(false)
    })
}

/// Encode a client **text** frame (FIN set, opcode 0x1, masked per RFC 6455).
pub fn encode_text_frame(payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | 0x1); // FIN + text opcode
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8); // MASK bit + 7-bit length
    } else if len <= 0xffff {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, &b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// The result of decoding one frame from a buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// A complete frame: its opcode, unmasked payload, and bytes consumed.
    Frame {
        opcode: u8,
        payload: Vec<u8>,
        consumed: usize,
    },
    /// Not enough bytes yet; read more and retry.
    Incomplete,
}

/// Decode one RFC 6455 frame from the front of `buf` (handles masked and
/// unmasked frames, and 7/16/64-bit lengths).
pub fn decode_frame(buf: &[u8]) -> Decoded {
    if buf.len() < 2 {
        return Decoded::Incomplete;
    }
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7f) as usize;
    let mut idx = 2;
    if len == 126 {
        if buf.len() < 4 {
            return Decoded::Incomplete;
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        idx = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Decoded::Incomplete;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[2..10]);
        len = u64::from_be_bytes(b) as usize;
        idx = 10;
    }
    let mask_key = if masked {
        if buf.len() < idx + 4 {
            return Decoded::Incomplete;
        }
        let key = [buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]];
        idx += 4;
        Some(key)
    } else {
        None
    };
    // `idx + len` must not overflow: a malformed server could send a 64-bit
    // length near usize::MAX (RFC 6455 forbids the high bit), which would wrap and
    // make the bounds check pass, then panic on the slice. checked_add turns that
    // into "need more bytes" — a frame that large never arrives, so no panic.
    let end = match idx.checked_add(len) {
        Some(end) => end,
        None => return Decoded::Incomplete,
    };
    if buf.len() < end {
        return Decoded::Incomplete;
    }
    let mut payload = buf[idx..end].to_vec();
    if let Some(key) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Decoded::Frame {
        opcode,
        payload,
        consumed: end,
    }
}

/// A WebSocket-backed [`BiDiTransport`]: JSON messages ride as text frames over a
/// TCP stream to the browser's remote agent. The codec is tested above; this
/// wraps it with socket I/O. End-to-end behaviour depends on a live BiDi browser.
pub struct WebSocketBiDiTransport {
    stream: TcpStream,
    rbuf: Vec<u8>,
    mask_state: u64,
}

impl WebSocketBiDiTransport {
    /// Connect to `addr` and perform the opening handshake for `path` (the BiDi
    /// WebSocket endpoint, e.g. `/session`). `host` is the `Host` header value.
    pub fn connect(addr: &str, host: &str, path: &str) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        // A fixed-but-distinctive client key; the server echoes a derived accept.
        let key = "x3JJHMbDL1EzLkh9GBhXDw==";
        stream.write_all(handshake_request(host, path, key).as_bytes())?;

        // Read until the end of the response headers.
        let mut resp = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "websocket handshake closed early",
                ));
            }
            resp.extend_from_slice(&chunk[..n]);
            if resp.windows(4).any(|w| w == b"\r\n\r\n") || resp.len() > 8192 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&resp);
        if !handshake_ok(&text, key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake was not accepted",
            ));
        }
        // A single read() may have returned the handshake response AND the first
        // frame(s) the server pushed right after. Seed the read buffer with any
        // bytes past the header terminator so that frame is not lost.
        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .unwrap_or(resp.len());
        Ok(WebSocketBiDiTransport {
            stream,
            rbuf: resp[header_end..].to_vec(),
            mask_state: 0x9E37_79B9_7F4A_7C15,
        })
    }

    /// Wrap an already-connected stream (handshake assumed done). Test-only: it
    /// lets `recv`/`send` be exercised over a loopback socket pair without a live
    /// browser.
    #[cfg(test)]
    fn from_stream(stream: TcpStream) -> Self {
        WebSocketBiDiTransport {
            stream,
            rbuf: Vec::new(),
            mask_state: 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Set a read timeout so a time-bounded capture loop can wake to check its
    /// deadline even when no frames arrive (a timed-out read surfaces as a
    /// `WouldBlock`/`TimedOut` error from [`BiDiTransport::recv`], which the
    /// caller treats as "no message yet").
    pub fn set_read_timeout(&mut self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    /// A fresh 4-byte masking key (varied per frame via SplitMix64; masking here
    /// is for protocol correctness, not secrecy — the server unmasks with the key
    /// we send).
    fn next_mask(&mut self) -> [u8; 4] {
        self.mask_state = self.mask_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.mask_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) as u32).to_le_bytes()
    }
}

impl BiDiTransport for WebSocketBiDiTransport {
    fn send(&mut self, message: &Value) -> io::Result<()> {
        let text = message.to_string();
        let mask = self.next_mask();
        self.stream
            .write_all(&encode_text_frame(text.as_bytes(), mask))
    }

    fn recv(&mut self) -> io::Result<Option<Value>> {
        loop {
            match decode_frame(&self.rbuf) {
                Decoded::Frame {
                    opcode,
                    payload,
                    consumed,
                } => {
                    self.rbuf.drain(..consumed);
                    match opcode {
                        0x1 => match serde_json::from_slice(&payload) {
                            Ok(value) => return Ok(Some(value)),
                            // A text frame that is not valid JSON (unexpected on a
                            // BiDi channel, or the leading fragment of a split
                            // message — decode_frame does not reassemble) is noise:
                            // skip it and read on. Returning Ok(None) here would be
                            // read as "connection closed" and silently end capture.
                            Err(_) => continue,
                        },
                        0x8 => return Ok(None), // close
                        // Ping/pong/binary/continuation: ignore and read on.
                        _ => continue,
                    }
                }
                Decoded::Incomplete => {
                    let mut chunk = [0u8; 8192];
                    let n = self.stream.read(&mut chunk)?;
                    if n == 0 {
                        return Ok(None);
                    }
                    self.rbuf.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn handshake_ok_requires_101_and_matching_accept() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let good = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(key)
        );
        assert!(handshake_ok(&good, key));
        // Wrong accept value.
        assert!(!handshake_ok(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
            key
        ));
        // Not a 101.
        assert!(!handshake_ok("HTTP/1.1 200 OK\r\n\r\n", key));
    }

    #[test]
    fn text_frame_round_trips_through_decode() {
        let payload = br#"{"id":1,"method":"session.subscribe"}"#;
        let frame = encode_text_frame(payload, [0xAA, 0xBB, 0xCC, 0xDD]);
        // The mask bit is set and the opcode is text.
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1] & 0x80, 0x80);
        match decode_frame(&frame) {
            Decoded::Frame {
                opcode,
                payload: got,
                consumed,
            } => {
                assert_eq!(opcode, 0x1);
                assert_eq!(got, payload);
                assert_eq!(consumed, frame.len());
            }
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    #[test]
    fn decode_reports_incomplete_until_whole_frame_present() {
        let frame = encode_text_frame(b"hello world", [1, 2, 3, 4]);
        // Every strict prefix is incomplete.
        for cut in 0..frame.len() {
            assert_eq!(decode_frame(&frame[..cut]), Decoded::Incomplete, "cut {cut}");
        }
        assert!(matches!(decode_frame(&frame), Decoded::Frame { .. }));
    }

    #[test]
    fn decode_handles_extended_16bit_length() {
        let payload = vec![b'x'; 200]; // forces the 126 / 16-bit length path
        let frame = encode_text_frame(&payload, [9, 8, 7, 6]);
        assert_eq!(frame[1] & 0x7f, 126);
        match decode_frame(&frame) {
            Decoded::Frame { payload: got, .. } => assert_eq!(got, payload),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    #[test]
    fn handshake_request_is_well_formed() {
        let req = handshake_request("127.0.0.1:9222", "/session", "abc123");
        assert!(req.starts_with("GET /session HTTP/1.1\r\n"));
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Sec-WebSocket-Key: abc123\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn decode_does_not_panic_on_an_overflowing_64bit_length() {
        // A malformed server (RFC forbids the high bit) claims a ~usize::MAX body.
        // The old `idx + len` wrapped, passed the bounds check, and panicked on the
        // slice; now it is reported Incomplete instead of crashing the codec.
        let mut frame = vec![0x81, 127];
        frame.extend_from_slice(&u64::MAX.to_be_bytes());
        frame.extend_from_slice(b"partial");
        assert_eq!(decode_frame(&frame), Decoded::Incomplete);
    }

    // A server-side unmasked text frame (what the browser sends us).
    fn server_text_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x81];
        let n = payload.len();
        assert!(n < 126, "test helper only needs the short-length path");
        f.push(n as u8);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn recv_skips_a_non_json_text_frame_instead_of_treating_it_as_close() {
        use std::io::Write as _;
        use std::net::{TcpListener, TcpStream};
        // Loopback pair: the "server" writes a garbage text frame followed by a
        // valid JSON one. recv must skip the garbage and return the JSON — NOT
        // return Ok(None) (which the capture loop reads as a closed connection).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.write_all(&server_text_frame(b"not json {{{")).unwrap();
            sock.write_all(&server_text_frame(br#"{"id":7,"ok":true}"#))
                .unwrap();
            // Keep the socket open briefly so the client reads both frames.
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let client = TcpStream::connect(addr).unwrap();
        let mut transport = WebSocketBiDiTransport::from_stream(client);
        let msg = transport.recv().unwrap().expect("should get the JSON frame");
        assert_eq!(msg["id"], 7);
        assert_eq!(msg["ok"], true);
        server.join().unwrap();
    }
}
