//! A QR code of the approval URL for the terminal (P1-A10), so the operator can open the page on a
//! phone. Drawn with Unicode half blocks, two module rows per text row, without colour codes.
//!
//! Light modules are drawn in the terminal's text colour and dark modules are left blank, which gives
//! the usual dark-on-light code on a dark terminal background; phone scanners also read the inverted
//! code a light background gives. The URL is always printed as text too.

use qrcodegen::{QrCode, QrCodeEcc};

/// Light border around the code, in modules. The standard asks for 4; 2 scans reliably on a screen and
/// keeps the code small.
const QUIET_ZONE: i32 = 2;

/// The QR code of `text` as lines of text, or `None` if it cannot be encoded.
pub fn render(text: &str) -> Option<String> {
    let code = QrCode::encode_text(text, QrCodeEcc::Low).ok()?;
    let size = code.size();
    // Outside the symbol everything is light (the quiet zone).
    let light = |x: i32, y: i32| !code.get_module(x, y);
    let mut out = String::new();
    let mut y = -QUIET_ZONE;
    while y < size + QUIET_ZONE {
        for x in -QUIET_ZONE..size + QUIET_ZONE {
            out.push(match (light(x, y), light(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_square_code_with_a_quiet_zone() {
        let url = "https://fleet.example.lan/onboard/WDJB-MJHT";
        let text = render(url).unwrap();
        let size = QrCode::encode_text(url, QrCodeEcc::Low).unwrap().size();
        let width = (size + 2 * QUIET_ZONE) as usize;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), width.div_ceil(2));
        assert!(lines.iter().all(|l| l.chars().count() == width));
        // The top rows are all quiet zone.
        assert!(lines[0].chars().all(|c| c == '█'));
        assert!(!text.contains('\u{1b}'), "no escape sequences");
    }
}
