//! Round 3 (PR #303): an Icon Composer zip is only what its central directory says. Every local
//! header names the same file, folders are empty, and entries run back to back with no bytes hiding
//! before, between or overlapping them.

use ainkrad_design::icon;

const J: &[u8] = br#"{"groups":[]}"#;

/// Stored entries `(local name, central name, data)`; `junk` puts a byte before each local header.
fn zip(files: &[(&str, &str, &[u8])], junk: bool, overlap_second: bool) -> Vec<u8> {
    let (mut out, mut cd, mut offs) = (Vec::new(), Vec::new(), Vec::new());
    for (local, central, data) in files {
        if junk {
            out.push(0);
        }
        let off = out.len() as u32;
        offs.push(off);
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let head = |sig: u32, name: &str, central_dir: bool, off: u32| {
            let mut h = sig.to_le_bytes().to_vec();
            if central_dir {
                h.extend(20u16.to_le_bytes());
            }
            h.extend(20u16.to_le_bytes());
            h.extend([0; 4]);
            h.extend([0; 4]);
            h.extend(crc.sum().to_le_bytes());
            h.extend((data.len() as u32).to_le_bytes());
            h.extend((data.len() as u32).to_le_bytes());
            h.extend((name.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes());
            if central_dir {
                h.extend([0; 10]);
                h.extend(off.to_le_bytes());
            }
            h.extend(name.as_bytes());
            h
        };
        out.extend(head(0x0403_4b50, local, false, 0));
        out.extend(*data);
        let at = if overlap_second && !cd.is_empty() {
            offs[0]
        } else {
            off
        };
        cd.extend(head(0x0201_4b50, central, true, at));
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
fn a_plain_contiguous_zip_passes() {
    assert_eq!(
        icon::check(&zip(&[("icon.json", "icon.json", J)], false, false)),
        Ok(())
    );
    let with_folder = zip(
        &[("A/", "A/", b""), ("A/icon.json", "A/icon.json", J)],
        false,
        false,
    );
    assert_eq!(icon::check(&with_folder), Ok(()));
}

#[test]
fn a_hidden_or_mismatched_zip_is_refused() {
    let cases = [
        (
            "local name differs",
            zip(&[("other.png", "icon.json", J)], false, false),
        ),
        (
            "folder holds data",
            zip(
                &[("A/", "A/", b"x"), ("icon.json", "icon.json", J)],
                false,
                false,
            ),
        ),
        (
            "bytes between entries",
            zip(&[("icon.json", "icon.json", J)], true, false),
        ),
        (
            "overlapping entries",
            zip(
                &[("icon.json", "icon.json", J), ("b.json", "b.json", J)],
                false,
                true,
            ),
        ),
    ];
    for (name, z) in cases {
        assert!(icon::check(&z).is_err(), "{name} passed");
    }
    let mut prefixed = vec![0u8; 4];
    prefixed.extend(zip(&[("icon.json", "icon.json", J)], false, false));
    assert!(
        icon::check(&prefixed).is_err(),
        "data before the first header passed"
    );
}
