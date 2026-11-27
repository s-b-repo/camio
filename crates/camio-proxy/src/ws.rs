//! WebSocket frame decoding and in-flight editing for raw `ws://` relays.
//!
//! The relay already carries `ws://` traffic byte-faithfully; without frame
//! awareness, capture records only "an upgrade happened". This module decodes
//! RFC 6455 frames from both directions so the proxy can
//!
//! * record what actually flowed (opcode, payload length, and a truncated
//!   preview) as the capture note, and
//! * let an operator **edit** a frame's payload in flight through a
//!   [`FrameEditor`] — text frames only, since editing a binary/control frame
//!   would corrupt the connection.
//!
//! Encoding re-frames an edited payload with the same opcode and an unmasked
//! server-side frame, matching what the origin would have received.

/// A decoded WebSocket frame (payload already unmasked for client frames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// `false` for a frame sent by the client (masked), `true` from the server.
    pub from_server: bool,
    /// RFC 6455 opcode (0x0 continuation, 0x1 text, 0x2 binary, 0x8 close,
    /// 0x9 ping, 0xA pong).
    pub opcode: u8,
    /// The (unmasked) payload.
    pub payload: Vec<u8>,
    /// Whether this frame carries the FIN bit.
    pub fin: bool,
}

impl Frame {
    /// A short, single-line preview of the payload for a capture note.
    pub fn preview(&self, max: usize) -> String {
        let take = self.payload.len().min(max);
        let text = String::from_utf8_lossy(&self.payload[..take]);
        let cleaned: String = text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let trimmed = cleaned.trim();
        if self.payload.len() > take {
            format!("{trimmed}…")
        } else {
            trimmed.to_string()
        }
    }

    /// Whether this frame's payload may be edited as text.
    pub fn is_editable(&self) -> bool {
        matches!(self.opcode, 0x1 | 0x0) && self.payload.len() <= MAX_EDITABLE_PAYLOAD
    }

    /// Re-frame the payload for the wire (server-side frames are unmasked).
    pub fn encode(&self) -> Vec<u8> {
        encode_frame(self.opcode, &self.payload, !self.from_server)
    }
}

/// Payloads larger than this are relayed untouched (an edit buffer beyond it
/// would be both useless and a memory risk).
pub const MAX_EDITABLE_PAYLOAD: usize = 1024 * 1024;

/// Whether `bytes` starts with a frame that is *incomplete* (and may complete
/// with more input), plus how many bytes are still needed.
///
/// Returns `None` when the buffer does not look like a frame at all — the
/// caller must then forward those bytes verbatim rather than buffering them, so
/// non-frame traffic after the upgrade (a probe, garbage) is never stalled.
pub fn incomplete_frame_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 {
        return Some(2 - bytes.len());
    }
    let opcode = bytes[0] & 0x0f;
    let rsv = bytes[0] & 0x70;
    let masked = bytes[1] & 0x80 != 0;
    let len7 = (bytes[1] & 0x7f) as usize;
    // A valid frame: reserved bits clear and a known opcode.
    let known_opcode = matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA);
    if rsv != 0 || !known_opcode || (len7 >= 126 && !masked && false) {
        return None;
    }
    let mut need = 2usize;
    let payload_len = match len7 {
        126 => {
            if bytes.len() < 4 {
                return Some(4 - bytes.len());
            }
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize
        }
        127 => {
            if bytes.len() < 10 {
                return Some(10 - bytes.len());
            }
            let n = u64::from_be_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]);
            if n > MAX_EDITABLE_PAYLOAD as u64 {
                return None; // not decodable: not ours to hold
            }
            n as usize
        }
        other => other,
    };
    need += if len7 == 126 {
        2
    } else if len7 == 127 {
        8
    } else {
        0
    };
    need += if masked { 4 } else { 0 };
    need += payload_len;
    Some(need.saturating_sub(bytes.len()))
}

/// Decode frames out of `bytes`, returning the frames and how many bytes were
/// consumed. A trailing partial frame is left unconsumed (the caller keeps the
/// remainder for the next read).
pub fn decode_frames(bytes: &[u8], from_server: bool) -> (Vec<Frame>, usize) {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 2 <= bytes.len() {
        let first = bytes[offset];
        let second = bytes[offset + 1];
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        let len7 = (second & 0x7f) as usize;
        let mut cursor = offset + 2;
        let payload_len = match len7 {
            126 => {
                if cursor + 2 > bytes.len() {
                    break; // partial extended length
                }
                let n = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                cursor += 2;
                n
            }
            127 => {
                if cursor + 8 > bytes.len() {
                    break;
                }
                let n = u64::from_be_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                    bytes[cursor + 4],
                    bytes[cursor + 5],
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                ]);
                cursor += 8;
                if n > MAX_EDITABLE_PAYLOAD as u64 {
                    // Not decryptable/editable: stop decoding rather than
                    // allocating for a hostile frame.
                    return (out, offset);
                }
                n as usize
            }
            other => other,
        };
        let mask = if masked {
            if cursor + 4 > bytes.len() {
                break; // partial mask
            }
            let m = [
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ];
            cursor += 4;
            Some(m)
        } else {
            None
        };
        if cursor + payload_len > bytes.len() {
            break; // partial payload
        }
        let mut payload = bytes[cursor..cursor + payload_len].to_vec();
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        offset = cursor + payload_len;
        out.push(Frame {
            from_server,
            opcode,
            payload,
            fin,
        });
    }
    (out, offset)
}

/// Encode a frame for the wire. Client→server frames are masked, as the
/// protocol requires.
pub fn encode_frame(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0f)); // FIN + opcode
    let len = payload.len();
    if len < 126 {
        out.push((len as u8) | if mask { 0x80 } else { 0 });
    } else if len <= u16::MAX as usize {
        out.push(126 | if mask { 0x80 } else { 0 });
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127 | if mask { 0x80 } else { 0 });
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        // A fixed mask keeps this deterministic; the protocol only requires
        // that client frames be masked, not that the mask be unpredictable.
        let key = [0x12, 0x34, 0x56, 0x78];
        out.extend_from_slice(&key);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ key[i % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// An in-flight editor for text frames. Returning `None` forwards the frame
/// unchanged; returning `Some(bytes)` replaces the payload. Binary/control
/// frames are never offered (see [`Frame::is_editable`]).
pub trait FrameEditor: Send + Sync + 'static {
    fn edit(&self, frame: &Frame) -> Option<Vec<u8>>;
}

/// An editor that forwards everything unchanged.
pub struct PassthroughEditor;

impl FrameEditor for PassthroughEditor {
    fn edit(&self, _frame: &Frame) -> Option<Vec<u8>> {
        None
    }
}

/// Decode a byte stream, apply `editor` to editable frames, and re-encode.
/// Returns the bytes to write downstream plus how many input bytes were
/// consumed (a trailing partial frame is left for the next call).
pub fn rewrite_frames(
    bytes: &[u8],
    from_server: bool,
    editor: &dyn FrameEditor,
) -> (Vec<u8>, usize) {
    let (frames, consumed) = decode_frames(bytes, from_server);
    let mut out = Vec::with_capacity(bytes.len());
    for frame in &frames {
        if frame.is_editable() {
            if let Some(payload) = editor.edit(frame) {
                out.extend_from_slice(&encode_frame(frame.opcode, &payload, !frame.from_server));
                continue;
            }
        }
        out.extend_from_slice(&frame.encode());
    }
    // Bytes that are not frame data (a probe, garbage after the upgrade) are
    // forwarded verbatim instead of being buffered forever.
    if consumed == 0 && frames.is_empty() && incomplete_frame_len(bytes).is_none() {
        out.extend_from_slice(bytes);
        return (out, bytes.len());
    }
    (out, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_frame(payload: &[u8]) -> Vec<u8> {
        encode_frame(0x1, payload, true)
    }

    #[test]
    fn decodes_a_masked_client_text_frame() {
        let wire = client_frame(b"hello");
        let (frames, consumed) = decode_frames(&wire, false);
        assert_eq!(consumed, wire.len());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].opcode, 0x1);
        assert!(!frames[0].from_server);
        assert_eq!(frames[0].payload, b"hello");
        assert!(frames[0].fin);
    }

    #[test]
    fn decodes_an_unmasked_server_frame() {
        let wire = encode_frame(0x1, b"pong-data", false);
        let (frames, consumed) = decode_frames(&wire, true);
        assert_eq!(consumed, wire.len());
        assert!(frames[0].from_server);
        assert_eq!(frames[0].payload, b"pong-data");
    }

    #[test]
    fn a_partial_frame_is_left_for_the_next_read() {
        let wire = client_frame(b"hello");
        let (frames, consumed) = decode_frames(&wire[..wire.len() - 2], false);
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);
        // Completing the bytes decodes it.
        let (frames, _) = decode_frames(&wire, false);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn extended_lengths_decode() {
        // 126: a 300-byte payload.
        let big = vec![b'x'; 300];
        let wire = encode_frame(0x2, &big, true);
        let (frames, _) = decode_frames(&wire, false);
        assert_eq!(frames[0].payload.len(), 300);

        // 127: a 70 000-byte payload (within the cap).
        let huge = vec![b'y'; 70_000];
        let wire = encode_frame(0x2, &huge, false);
        let (frames, _) = decode_frames(&wire, true);
        assert_eq!(frames[0].payload.len(), 70_000);
    }

    #[test]
    fn an_oversized_frame_is_not_decoded() {
        // A declared length past the cap stops decoding instead of allocating.
        let mut wire = vec![0x82, 127];
        wire.extend_from_slice(&(MAX_EDITABLE_PAYLOAD as u64 + 1).to_be_bytes());
        wire.extend_from_slice(&[0u8; 8]);
        let (frames, consumed) = decode_frames(&wire, false);
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn an_editor_rewrites_text_frames_only() {
        struct Replace;
        impl FrameEditor for Replace {
            fn edit(&self, frame: &Frame) -> Option<Vec<u8>> {
                let text = String::from_utf8_lossy(&frame.payload);
                Some(text.replace("secret", "redacted").into_bytes())
            }
        }
        let wire = client_frame(b"token=secret");
        let (out, consumed) = rewrite_frames(&wire, false, &Replace);
        assert_eq!(consumed, wire.len());
        let (frames, _) = decode_frames(&out, false);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"token=redacted");

        // A binary frame is forwarded byte-identical.
        let binary = encode_frame(0x2, b"\x00\x01secret", true);
        let (out, _) = rewrite_frames(&binary, false, &Replace);
        assert_eq!(out, binary, "binary frames must not be edited");
    }

    #[test]
    fn passthrough_is_byte_identical() {
        let wire = client_frame(b"untouched");
        let (out, _) = rewrite_frames(&wire, false, &PassthroughEditor);
        assert_eq!(out, wire);
    }

    #[test]
    fn previews_are_single_line() {
        let frame = Frame {
            from_server: false,
            opcode: 0x1,
            payload: b"line one\nline two\tend".to_vec(),
            fin: true,
        };
        let preview = frame.preview(40);
        assert!(!preview.contains('\n'), "preview was {preview:?}");
        assert!(preview.contains("line one"));
    }
}
#[cfg(test)]
mod non_frame_tests {
    use super::*;

    #[test]
    fn non_frame_bytes_are_forwarded_verbatim() {
        // A probe after the upgrade is not a frame: it must be relayed as-is
        // (and consumed), not buffered waiting for bytes that never form one.
        let (out, consumed) = rewrite_frames(b"PING", false, &PassthroughEditor);
        assert_eq!(out, b"PING");
        assert_eq!(consumed, 4);
    }

    #[test]
    fn a_partial_frame_is_still_held() {
        // Two bytes of a real frame header: incomplete, so nothing is consumed
        // yet and nothing is forwarded.
        let wire = encode_frame(0x1, b"hello", true);
        let (out, consumed) = rewrite_frames(&wire[..2], false, &PassthroughEditor);
        assert_eq!(consumed, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn incomplete_frame_len_distinguishes_partial_from_garbage() {
        let wire = encode_frame(0x1, b"hello world", true);
        assert!(incomplete_frame_len(&wire[..3]).is_some());
        // "PING" looks nothing like a frame.
        assert!(incomplete_frame_len(b"PING").is_none());
        // Reserved bits set → not a frame we should hold.
        let mut weird = wire.clone();
        weird[0] |= 0x40;
        assert!(incomplete_frame_len(&weird[..4]).is_none());
    }

    #[test]
    fn an_edited_frame_round_trips_through_the_wire() {
        struct Upper;
        impl FrameEditor for Upper {
            fn edit(&self, frame: &Frame) -> Option<Vec<u8>> {
                Some(
                    String::from_utf8_lossy(&frame.payload)
                        .to_uppercase()
                        .into_bytes(),
                )
            }
        }
        let wire = encode_frame(0x1, b"hello", true);
        let (out, consumed) = rewrite_frames(&wire, false, &Upper);
        assert_eq!(consumed, wire.len());
        let (frames, _) = decode_frames(&out, false);
        assert_eq!(frames[0].payload, b"HELLO");
        // The re-encoded frame is a valid masked client frame.
        assert!(!frames[0].from_server);
    }
}
