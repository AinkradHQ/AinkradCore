//! Round-2 review fix (PR #303): an `.icon` zip with an SVG layer is refused outright, however
//! plain the SVG, while the same zip with a PNG layer passes.

use ainkrad_design::icon;

/// A stored (uncompressed) zip of `(name, bytes)`.
fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut out, mut cd) = (Vec::new(), Vec::new());
    for (name, data) in files {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let off = out.len() as u32;
        let head = |sig: u32, central: bool| {
            let mut h = sig.to_le_bytes().to_vec();
            if central {
                h.extend(20u16.to_le_bytes());
            }
            h.extend(20u16.to_le_bytes());
            h.extend(0u16.to_le_bytes());
            h.extend(0u16.to_le_bytes());
            h.extend([0; 4]);
            h.extend(crc.sum().to_le_bytes());
            h.extend((data.len() as u32).to_le_bytes());
            h.extend((data.len() as u32).to_le_bytes());
            h.extend((name.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes());
            if central {
                h.extend([0; 10]);
                h.extend(off.to_le_bytes());
            }
            h.extend(name.as_bytes());
            h
        };
        out.extend(head(0x0403_4b50, false));
        cd.extend(head(0x0201_4b50, true));
        out.extend(*data);
    }
    let (cd_off, cd_len) = (out.len() as u32, cd.len() as u32);
    out.extend(cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend(cd_len.to_le_bytes());
    out.extend(cd_off.to_le_bytes());
    out.extend([0; 2]);
    out
}

#[test]
fn an_svg_layer_is_refused_however_plain() {
    let j: &[u8] = br#"{"groups":[]}"#;
    let png = design_render::synth::png(1);
    assert_eq!(
        icon::check(&zip(&[
            ("App.icon/icon.json", j),
            ("App.icon/Assets/a.png", &png)
        ])),
        Ok(())
    );
    for svg in [
        &b"<svg xmlns='http://www.w3.org/2000/svg'/>"[..],
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"1\" height=\"1\"/></svg>",
        b"<svg xmlns='http://www.w3.org/2000/svg'><use href='#a'/></svg>",
        b"<svg><script>alert(1)</script></svg>",
    ] {
        for name in ["App.icon/Assets/a.svg", "App.icon/Assets/A.SVG"] {
            let e = icon::check(&zip(&[("App.icon/icon.json", j), (name, svg)])).unwrap_err();
            assert!(e.contains("SVG"), "{name}: {e}");
        }
    }
}
