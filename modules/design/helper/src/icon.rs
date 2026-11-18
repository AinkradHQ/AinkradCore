//! The Icon Composer `.icon` check: a zip of `icon.json` plus image layers. Every length the zip
//! states is checked against the file before it is used; entries are inflated with a hard cap and
//! their CRC compared, so a zip bomb, a lying header or a path that climbs out is refused before any
//! layer reaches an image decoder. Only `icon.json` and `.png`/`.jpg`/`.jpeg`/`.svg` layers are allowed
//! (directories aside), and an SVG layer with script, entities or an outside link is refused.

use std::io::Read;

use design_render::Assets;

const MAX_ENTRIES: usize = 1_000;
const MAX_ENTRY: u64 = 25 << 20;
const MAX_TOTAL: u64 = 64 << 20;
const MAX_NAME: usize = 512;

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?) as usize)
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME
        && !n.starts_with('/')
        && !n.contains(['\0', '\\'])
        && n.split('/').all(|s| s != "..")
}

struct Entry {
    name: String,
    method: usize,
    crc: u32,
    comp: u64,
    size: u64,
    local: usize,
}

/// The central directory, every field bounds-checked.
fn entries(b: &[u8]) -> Result<Vec<Entry>, &'static str> {
    const BAD: &str = "the zip is damaged";
    // The end record: in the last 64 KiB + 22 bytes.
    let from = b.len().saturating_sub(65_535 + 22);
    let eocd = (from..b.len().saturating_sub(21))
        .rev()
        .find(|&i| u32_at(b, i) == Some(0x0605_4b50))
        .ok_or(BAD)?;
    let count = u16_at(b, eocd + 10).ok_or(BAD)?;
    let cd = u32_at(b, eocd + 16).ok_or(BAD)? as usize;
    if count > MAX_ENTRIES || count == 0xffff || cd == 0xffff_ffff {
        return Err("the zip has too many entries");
    }
    let mut out = Vec::with_capacity(count);
    let mut i = cd;
    for _ in 0..count {
        if u32_at(b, i) != Some(0x0201_4b50) {
            return Err(BAD);
        }
        let flags = u16_at(b, i + 8).ok_or(BAD)?;
        let method = u16_at(b, i + 10).ok_or(BAD)?;
        let crc = u32_at(b, i + 16).ok_or(BAD)?;
        let comp = u32_at(b, i + 20).ok_or(BAD)?;
        let size = u32_at(b, i + 24).ok_or(BAD)?;
        let (nl, xl, cl) = (
            u16_at(b, i + 28).ok_or(BAD)?,
            u16_at(b, i + 30).ok_or(BAD)?,
            u16_at(b, i + 32).ok_or(BAD)?,
        );
        let local = u32_at(b, i + 42).ok_or(BAD)? as usize;
        if comp == u32::MAX || size == u32::MAX || local == u32::MAX as usize {
            return Err("ZIP64 is not supported");
        }
        if flags & 1 != 0 {
            return Err("an encrypted zip is not supported");
        }
        let name = b.get(i + 46..i + 46 + nl).ok_or(BAD)?;
        let name = std::str::from_utf8(name).map_err(|_| "a file name is not UTF-8")?;
        if !name_ok(name) {
            return Err("a file name is not a plain relative path");
        }
        out.push(Entry {
            name: name.to_owned(),
            method,
            crc,
            comp: comp.into(),
            size: size.into(),
            local,
        });
        i += 46 + nl + xl + cl;
    }
    Ok(out)
}

/// One entry's bytes: located through its local header, inflated with a cap, CRC checked.
fn read(b: &[u8], e: &Entry) -> Result<Vec<u8>, &'static str> {
    const BAD: &str = "the zip is damaged";
    if u32_at(b, e.local) != Some(0x0403_4b50) {
        return Err(BAD);
    }
    let start =
        e.local + 30 + u16_at(b, e.local + 26).ok_or(BAD)? + u16_at(b, e.local + 28).ok_or(BAD)?;
    let data = b.get(start..start + e.comp as usize).ok_or(BAD)?;
    let mut out = Vec::new();
    match e.method {
        0 => out.extend_from_slice(data),
        8 => {
            flate2::read::DeflateDecoder::new(data)
                .take(e.size + 1)
                .read_to_end(&mut out)
                .map_err(|_| BAD)?;
        }
        _ => return Err("the zip uses an unsupported compression"),
    }
    if out.len() as u64 != e.size {
        return Err("an entry's size does not match the zip");
    }
    let mut crc = flate2::Crc::new();
    crc.update(&out);
    if crc.sum() != e.crc {
        return Err("an entry's checksum does not match");
    }
    Ok(out)
}

/// An SVG layer is not drawn by this renderer, but it is served later: refuse script, entities
/// and any reference that is not to its own fragment.
fn svg_ok(b: &[u8]) -> Result<(), &'static str> {
    let text = std::str::from_utf8(b).map_err(|_| "an SVG layer is not UTF-8")?;
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<svg") {
        return Err("an SVG layer is not SVG");
    }
    if lower.contains("<script") || lower.contains("<!entity") || lower.contains("<!doctype") {
        return Err("an SVG layer has script or entities");
    }
    for (i, _) in lower.match_indices("href") {
        let rest = lower[i + 4..].trim_start();
        let Some(v) = rest.strip_prefix('=') else {
            continue;
        };
        let v = v.trim_start().trim_start_matches(['"', '\'']);
        if !v.starts_with('#') {
            return Err("an SVG layer links outside itself");
        }
    }
    Ok(())
}

pub fn check(b: &[u8]) -> Result<(), &'static str> {
    let list = entries(b)?;
    let mut total = 0u64;
    for e in &list {
        if e.size > MAX_ENTRY {
            return Err("an entry is too large");
        }
        total += e.size;
    }
    if total > MAX_TOTAL {
        return Err("the zip unpacks too large");
    }
    let mut manifest = false;
    let mut assets = Assets::default();
    for e in list.iter().filter(|e| !e.name.ends_with('/')) {
        let bytes = read(b, e)?;
        let lower = e.name.to_ascii_lowercase();
        if lower == "icon.json" || lower.ends_with("/icon.json") {
            let v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| "icon.json is not valid JSON")?;
            manifest |= v.is_object();
        } else if [".png", ".jpg", ".jpeg"].iter().any(|x| lower.ends_with(x)) {
            if !crate::ops::image_ok(&bytes) {
                return Err("an image layer is not an image of an allowed size");
            }
            assets.add(&e.name, &bytes);
            if assets.image(&e.name).is_none() {
                return Err("an image layer does not decode");
            }
        } else if lower.ends_with(".svg") {
            svg_ok(&bytes)?;
        } else {
            return Err("the zip holds a file that is not icon.json or an image layer");
        }
    }
    if !manifest {
        return Err("the zip has no icon.json");
    }
    Ok(())
}
