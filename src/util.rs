#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::{Context, Result, bail, ensure};

pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn find_masked_pattern(haystack: &[u8], pattern: &[u8], mask: Option<&[u8]>) -> Option<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return None;
    }
    if let Some(mask) = mask {
        if mask.len() != pattern.len() {
            return None;
        }
    }

    (0..=haystack.len() - pattern.len()).find(|candidate| {
        pattern.iter().enumerate().all(|(index, expected)| {
            mask.is_some_and(|mask| mask[index] == 0xff) || haystack[candidate + index] == *expected
        })
    })
}

pub fn find_unique_masked_pattern(
    haystack: &[u8],
    pattern: &[u8],
    mask: Option<&[u8]>,
    name: &str,
) -> Result<usize> {
    let first = find_masked_pattern(haystack, pattern, mask)
        .with_context(|| format!("missing {name} pattern"))?;
    let rest = &haystack[first + 1..];
    if find_masked_pattern(rest, pattern, mask).is_some() {
        bail!("{name} pattern is ambiguous");
    }
    Ok(first)
}

pub fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("missing u32 at offset {offset}"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

pub fn le_u24(bytes: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes
        .get(offset..offset + 3)
        .with_context(|| format!("missing u24 at offset {offset}"))?;
    Ok(bytes[0] as u32 | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16))
}

pub fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let bytes = bytes
        .get(offset..offset + 2)
        .with_context(|| format!("missing u16 at offset {offset}"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

pub fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let bytes = bytes
        .get(offset..offset + 8)
        .with_context(|| format!("missing u64 at offset {offset}"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

pub fn write_le_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset + 2)
        .with_context(|| format!("missing u16 write target at offset {offset}"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn write_le_u24(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset + 3)
        .with_context(|| format!("missing u24 write target at offset {offset}"))?;
    target.copy_from_slice(&value.to_le_bytes()[..3]);
    Ok(())
}

pub fn write_le_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset + 4)
        .with_context(|| format!("missing u32 write target at offset {offset}"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn write_le_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset + 8)
        .with_context(|| format!("missing u64 write target at offset {offset}"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn align(base: usize, offset: usize, alignment: usize) -> usize {
    let relative = offset - base;
    if relative.is_multiple_of(alignment) {
        offset
    } else {
        ((relative / alignment) + 1) * alignment + base
    }
}

pub fn checksum8(bytes: &[u8]) -> u8 {
    let checksum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    0u8.wrapping_sub(checksum)
}

pub fn checksum16_le(bytes: &[u8]) -> u16 {
    let checksum = bytes.chunks_exact(2).fold(0u16, |sum, chunk| {
        sum.wrapping_add(u16::from_le_bytes([chunk[0], chunk[1]]))
    });
    0u16.wrapping_sub(checksum)
}

pub fn format_guid(bytes: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn decode_utf16_name(bytes: &[u8]) -> String {
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();

    String::from_utf16_lossy(&words)
}

pub fn parse_u16(value: &str) -> Result<u16, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        value.parse::<u16>().map_err(|err| err.to_string())
    }
}

pub fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        value.parse::<u32>().map_err(|err| err.to_string())
    }
}

pub fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn hex_dump_compact(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

pub fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    ensure!(value.len().is_multiple_of(2), "hex string has odd length");

    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .with_context(|| format!("invalid hex byte at offset {index}"))
        })
        .collect()
}

pub fn ascii_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

pub fn ascii_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
