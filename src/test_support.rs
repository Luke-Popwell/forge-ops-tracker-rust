// Shared by the hand-rolled HTTP servers in this crate's own tests (see each module's tests).
// Not part of the crate's public API: compiled only for tests.

use std::io::Read;
use std::net::TcpStream;

/// Reads one whole HTTP request off `stream`: the header block *and* the Content-Length-declared
/// body after it. The earlier version of each of these servers stopped reading the moment it saw
/// the blank line ending the headers, then answered and dropped the connection: when the client
/// (ureq) hadn't finished sending its body yet, closing a socket with unread data still in its
/// receive buffer makes the OS send a reset instead of a clean close, which surfaced as ureq
/// failing (sometimes panicking inside its own `read_exact`) and made ~40% of test runs fail at
/// random, confirmed by stashing every other change and repeating the suite on the original code.
pub(crate) fn read_full_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = [0u8; 8192];
    let mut total = Vec::new();
    loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        total.extend_from_slice(&buf[..n]);

        let Some(pos) = total.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let content_length: usize = String::from_utf8_lossy(&total[..pos])
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if total.len() >= pos + 4 + content_length {
            break;
        }
    }
    total
}
