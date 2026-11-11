//! Bounded output capture (P3-A03, threat model O6).
//!
//! A task's standard output and standard error go to one pipe, and everything read from it goes
//! through a [`Capture`]: the first [`HEAD_BYTES`] and the last [`TAIL_BYTES`] are kept, and the
//! bytes in between are counted and dropped as they arrive. Memory stays bounded however much a
//! task prints (gigabytes included), and the text keeps both the start and the end, where errors
//! usually are, as the server does with its own limit (P3-S04).
//!
//! The text sent is at most [`MAX_OUTPUT_CHARS`] characters, the most `task-result.request` takes.
//! When anything was dropped, a marker line says how much, and `output_truncated` is set.

/// Bytes kept from the start of the output.
pub const HEAD_BYTES: usize = 64_000;
/// Bytes kept from the end of the output.
pub const TAIL_BYTES: usize = 64_000;
/// The most characters `task-result.request` accepts in `output`.
pub const MAX_OUTPUT_CHARS: usize = 131_072;

/// Output read so far, bounded.
#[derive(Debug, Default, Clone)]
pub struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
    dropped: u64,
    /// Lines the agent itself added (deadline passed, task left running, ...), kept whole.
    notes: Vec<String>,
}

impl Capture {
    /// Adds bytes read from the task, keeping at most the head and the tail.
    pub fn push(&mut self, mut bytes: &[u8]) {
        if self.head.len() < HEAD_BYTES {
            let take = bytes.len().min(HEAD_BYTES - self.head.len());
            self.head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        if bytes.is_empty() {
            return;
        }
        if bytes.len() >= TAIL_BYTES {
            self.dropped += (self.tail.len() + bytes.len() - TAIL_BYTES) as u64;
            self.tail.clear();
            self.tail
                .extend_from_slice(&bytes[bytes.len() - TAIL_BYTES..]);
            return;
        }
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > TAIL_BYTES {
            let excess = self.tail.len() - TAIL_BYTES;
            self.dropped += excess as u64;
            self.tail.drain(..excess);
        }
    }

    /// Adds a line written by the agent, not the task, shown after the task's output.
    pub fn note(&mut self, line: &str) {
        if self.notes.len() < 8 {
            self.notes
                .push(crate::logging::sanitize(line, 500).trim_end().to_owned());
        }
    }

    /// The text to report and whether it was truncated.
    pub fn finish(&self) -> (String, bool) {
        let mut text = String::from_utf8_lossy(&self.head).into_owned();
        if self.dropped > 0 {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!(
                "[fleet-agent: {} bytes of output were cut here]\n",
                self.dropped
            ));
        }
        text.push_str(&String::from_utf8_lossy(&self.tail));
        for note in &self.notes {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str("[fleet-agent: ");
            text.push_str(note);
            text.push_str("]\n");
        }
        let mut truncated = self.dropped > 0;
        if text.chars().count() > MAX_OUTPUT_CHARS {
            // Only invalid UTF-8 replaced by U+FFFD could make this happen; keep the start.
            text = text.chars().take(MAX_OUTPUT_CHARS).collect();
            truncated = true;
        }
        (text, truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_output_is_kept_whole() {
        let mut capture = Capture::default();
        capture.push(b"hello\n");
        capture.push(b"world\n");
        assert_eq!(capture.finish(), ("hello\nworld\n".to_owned(), false));
    }

    #[test]
    fn large_output_keeps_the_start_and_the_end_with_a_marker() {
        let mut capture = Capture::default();
        capture.push(&vec![b'a'; HEAD_BYTES]);
        for _ in 0..1000 {
            capture.push(&vec![b'b'; 10_000]);
        }
        capture.push(b"the end\n");
        let (text, truncated) = capture.finish();
        assert!(truncated);
        assert!(text.starts_with(&"a".repeat(HEAD_BYTES)));
        assert!(text.ends_with("the end\n"));
        let dropped = 1000 * 10_000 + 8 - TAIL_BYTES;
        assert!(text.contains(&format!(
            "[fleet-agent: {dropped} bytes of output were cut here]"
        )));
        assert!(text.chars().count() <= MAX_OUTPUT_CHARS);
    }

    #[test]
    fn one_huge_chunk_and_many_small_ones_drop_the_same() {
        let mut one = Capture::default();
        one.push(&vec![b'x'; 1_000_000]);
        let mut many = Capture::default();
        for _ in 0..1_000_000 / 1000 {
            many.push(&[b'x'; 1000]);
        }
        assert_eq!(one.finish(), many.finish());
    }

    #[test]
    fn invalid_utf8_never_exceeds_the_limit_and_notes_come_last() {
        let mut capture = Capture::default();
        capture.push(&vec![0xff; 400_000]);
        capture.note("the task ran past its deadline");
        let (text, truncated) = capture.finish();
        assert!(truncated);
        assert!(text.chars().count() <= MAX_OUTPUT_CHARS);

        let mut capture = Capture::default();
        capture.push(b"partial line");
        capture.note("stopped\nhere");
        assert_eq!(
            capture.finish().0,
            "partial line\n[fleet-agent: stopped here]\n"
        );
    }
}
