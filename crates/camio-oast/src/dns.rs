//! A minimal DNS responder for pure-DNS exfiltration correlation (plan §F15).
//!
//! Blind-injection probes sometimes only get a *name lookup* out of the target
//! (a blind SSRF to a `hostname`, an XXE with an external DTD, an SMTP-style
//! injection) — no HTTP request ever lands on the collector, so the HTTP
//! collector alone cannot correlate.
//!
//! This responder answers `A` queries for `<token>.<base>` with the collector's
//! own address (so the target's resolver accepts the answer) and records the
//! query as an interaction correlated by the leftmost label. It implements
//! exactly the slice of RFC 1035 needed for that: question parsing, an answer
//! with a single `A` record, and a compression-free response. Anything else
//! (other qtypes, malformed packets) is answered with `NOTIMP`/`FORMERR` rather
//! than guessed at, and no query is ever *cached* or forwarded.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Where a correlated DNS lookup is recorded. Implemented by the in-memory
/// [`Collector`](crate::Collector) and by the durable collector, so a DNS
/// responder persists exactly like the HTTP path.
pub trait DnsSink: Send + Sync + 'static {
    /// Record a DNS lookup of `qname` correlated to `token`.
    fn note_dns_lookup(&self, token: &str, qname: &str) -> Result<(), String>;
}

impl DnsSink for crate::Collector {
    fn note_dns_lookup(&self, token: &str, qname: &str) -> Result<(), String> {
        let interaction = crate::Interaction {
            id: 0,
            token: Some(token.to_string()),
            method: "DNS".into(),
            target: qname.to_string(),
            host: Some(qname.to_string()),
            source: "-".into(),
            received_at_ms: crate::now_ms(),
            headers: camio_core::HeaderList::new(),
            body: camio_core::Body::from_text(format!("DNS A query for {qname}")),
        };
        self.record_for_test(&interaction);
        Ok(())
    }
}

/// The UDP listener + query handler.
pub struct DnsResponder {
    sink: Arc<dyn DnsSink>,
    /// The address answers point at (the collector's own IP).
    answer_ip: [u8; 4],
    shutdown: Arc<AtomicBool>,
}

impl DnsResponder {
    pub fn new(sink: Arc<dyn DnsSink>, answer_ip: [u8; 4]) -> Self {
        DnsResponder {
            sink,
            answer_ip,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Serve DNS on `addr` until stopped. Blocking; use [`DnsResponder::spawn`]
    /// for a background responder.
    pub fn serve(self, addr: impl ToSocketAddrs) -> std::io::Result<()> {
        let socket = UdpSocket::bind(addr)?;
        self.serve_with_socket(socket)
    }

    /// Serve on an already-bound socket.
    pub fn serve_with_socket(self, socket: UdpSocket) -> std::io::Result<()> {
        let mut buf = [0u8; 512];
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            let (n, peer) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => continue,
            };
            if let Some(response) = self.handle_query(&buf[..n]) {
                let _ = socket.send_to(&response, peer);
            }
        }
    }

    /// Spawn the responder on `socket` in the background; returns a handle that
    /// stops it.
    pub fn spawn(self, socket: UdpSocket) -> std::io::Result<DnsHandle> {
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        let shutdown = self.shutdown.clone();
        let join = std::thread::Builder::new()
            .name("camio-oast-dns".into())
            .spawn(move || {
                let _ = self.serve_with_socket(socket);
            })?;
        Ok(DnsHandle {
            shutdown,
            join: Some(join),
        })
    }

    /// Handle one query, returning the response bytes (or `None` when the query
    /// is not ours to answer).
    fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_query(query)?;
        // The leftmost label is the correlation token when it looks like one.
        let first = parsed.qname.split('.').next().unwrap_or("");
        if !crate::is_token(first) {
            return Some(self_notimp(query));
        }
        let token = first.to_ascii_lowercase();

        // Record the lookup as an interaction (correlated by token) through the
        // sink, so a durable collector persists it like any other callback.
        let _ = self.sink.note_dns_lookup(&token, &parsed.qname);

        Some(answer(query, &parsed.qname, self.answer_ip, parsed.qtype))
    }
}

/// A stoppable DNS responder handle.
pub struct DnsHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl DnsHandle {
    pub fn stop_and_join(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// A parsed question.
struct Question {
    qname: String,
    qtype: u16,
}

/// Parse the header + question of a DNS query. Returns `None` for anything that
/// is not a well-formed standard query with exactly one question we understand.
fn parse_query(query: &[u8]) -> Option<Question> {
    if query.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    // QR must be 0 (a query) and opcode 0 (standard).
    if flags & 0x8000 != 0 || (flags >> 11) & 0xF != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    // Walk the qname labels (no compression pointers in a question name).
    let mut offset = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *query.get(offset)? as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        // A label length byte of 0xC0+ would be a compression pointer, which a
        // question must not use.
        if len & 0xC0 != 0 {
            return None;
        }
        offset += 1;
        let end = offset.checked_add(len)?;
        if end > query.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&query[offset..end]).to_string());
        offset = end;
    }
    let qtype = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    let qclass = u16::from_be_bytes([*query.get(offset + 2)?, *query.get(offset + 3)?]);
    if qclass != 1 {
        return None; // IN only
    }
    Some(Question {
        qname: labels.join("."),
        qtype,
    })
}

/// Build an `A` answer (or NOTIMP for other qtypes).
fn answer(query: &[u8], qname: &str, ip: [u8; 4], qtype: u16) -> Vec<u8> {
    if qtype != 1 {
        return self_notimp(query);
    }
    let mut out = Vec::with_capacity(query.len() + 16);
    // Header: same id, QR=1, opcode 0, AA=1, rcode 0, one question/answer.
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&0x8400u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
                                                // Question, echoed verbatim.
    out.extend_from_slice(&query[12..]);
    // Answer: a compression pointer to the question name (offset 12).
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // type A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&60u32.to_be_bytes()); // TTL
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    out.extend_from_slice(&ip);
    let _ = qname;
    out
}

/// Alias so the responder can call the module's NOTIMP builder.
fn self_notimp(query: &[u8]) -> Vec<u8> {
    notimp(query)
}

/// A NOTIMP response with the question echoed when possible.
fn notimp(query: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len());
    if query.len() >= 12 {
        out.extend_from_slice(&query[..2]);
        out.extend_from_slice(&0x8404u16.to_be_bytes()); // QR + rcode 4 (NOTIMP)
        let qd = u16::from_be_bytes([query[4], query[5]]);
        out.extend_from_slice(&qd.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&query[12..]);
    }
    out
}

use std::net::ToSocketAddrs;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Collector;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34]; // id
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    #[test]
    fn a_token_subdomain_query_is_answered_and_recorded() {
        let collector = Collector::new("127.0.0.1:0");
        let responder = DnsResponder::new(collector.clone(), [127, 0, 0, 1]);
        let q = query("deadbeefcafe0123.camio.test", 1);
        let resp = responder.handle_query(&q).expect("a response");

        // The response is an answer with our A record.
        assert_eq!(resp[3] & 0x0F, 0, "rcode must be NOERROR");
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 1);
        assert!(resp.ends_with(&[127, 0, 0, 1]));
        // The lookup is recorded against the token.
        let found = collector.for_token("deadbeefcafe0123");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "DNS");
        assert_eq!(found[0].target, "deadbeefcafe0123.camio.test");
    }

    #[test]
    fn a_non_token_name_is_not_recorded() {
        let collector = Collector::new("127.0.0.1:0");
        let responder = DnsResponder::new(collector.clone(), [127, 0, 0, 1]);
        let q = query("www.example.com", 1);
        let resp = responder.handle_query(&q).expect("a response");
        // NOTIMP for a name we do not recognise as ours.
        assert_eq!(resp[3] & 0x0F, 4, "NOTIMP for a name we do not recognise");
        assert_eq!(collector.len(), 0);
    }

    #[test]
    fn other_qtypes_are_not_answered_with_a_record() {
        let collector = Collector::new("127.0.0.1:0");
        let responder = DnsResponder::new(collector, [127, 0, 0, 1]);
        // AAAA for a token name: recorded (the target asked), but NOTIMP.
        let q = query("deadbeefcafe0123.camio.test", 28);
        let resp = responder.handle_query(&q).expect("a response");
        assert_eq!(resp[3] & 0x0F, 4, "AAAA is not implemented");
    }

    #[test]
    fn malformed_queries_are_ignored() {
        let collector = Collector::new("127.0.0.1:0");
        let responder = DnsResponder::new(collector.clone(), [127, 0, 0, 1]);
        assert!(responder.handle_query(&[0u8; 4]).is_none());
        assert!(responder.handle_query(&[]).is_none());
        // A response (QR=1) is not a query.
        let mut response_like = query("deadbeefcafe0123.camio.test", 1);
        response_like[2] |= 0x80;
        assert!(responder.handle_query(&response_like).is_none());
        assert_eq!(collector.len(), 0);
    }
}
#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::Collector;
    use std::net::UdpSocket;

    /// End-to-end over a real UDP socket: a query sent on the wire gets an
    /// answer and a recorded interaction.
    #[test]
    fn answers_over_udp_and_records_the_lookup() {
        let collector = Collector::new("127.0.0.1:0");
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server_socket.local_addr().unwrap();
        let responder = DnsResponder::new(collector.clone(), [127, 0, 0, 1]);
        let handle = responder.spawn(server_socket).unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut q = vec![0xab, 0xcd];
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in "cafebabe00112233.camio.test".split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]); // type A, class IN
        client.send_to(&q, addr).unwrap();

        let mut buf = [0u8; 512];
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..2], &[0xab, 0xcd], "the id is echoed");
        assert_eq!(buf[3] & 0x0F, 0, "NOERROR");
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1, "one answer");
        assert!(buf[..n].ends_with(&[127, 0, 0, 1]));
        let found = collector.for_token("cafebabe00112233");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "DNS");

        handle.stop_and_join();
    }
}
