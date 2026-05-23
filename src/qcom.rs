#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "cli")]
use std::{
    fs,
    io::{Cursor, Read},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
#[cfg(feature = "cli")]
use zip::ZipArchive;

#[cfg(feature = "std")]
use crate::util::hex_dump_compact;
use crate::util::{find_bytes, le_u16, le_u32, le_u64, parse_hex_bytes};

pub struct QcomSource {
    pub format: &'static str,
    pub bytes: Vec<u8>,
}

pub struct QcomCandidate {
    pub name: String,
    pub format: &'static str,
    pub bytes: Vec<u8>,
}

pub struct MatchingLoader {
    pub name: String,
    pub format: &'static str,
    pub size: usize,
    pub root_key_hash: Vec<u8>,
}

pub struct QualcommImage {
    pub header_type: &'static str,
    pub image_offset: u32,
    pub header_offset: u32,
    pub image_address: u32,
    pub image_size: u32,
    pub code_size: u32,
    pub signature_address: u32,
    pub signature_size: u32,
    pub certificates_address: u32,
    pub certificates_size: u32,
    pub root_key_hash: Option<Vec<u8>>,
}

impl QualcommImage {
    pub fn parse(bytes: &[u8], offset: u32) -> Result<Self> {
        let mut image_offset = offset;
        let header_offset;
        let header_type;

        if bytes.get(offset as usize..offset as usize + 4) == Some(b"\x7fELF") {
            header_type = "elf";
            let elf_class = *bytes
                .get(offset as usize + 4)
                .context("ELF header missing class")?;
            if elf_class == 1 {
                let program_header_offset = offset
                    .checked_add(le_u32(bytes, offset as usize + 0x1c)?)
                    .context("ELF program header offset overflow")?;
                let program_header_entry_size = le_u16(bytes, offset as usize + 0x2a)? as u32;
                let hash_program_header_offset = program_header_offset
                    .checked_add(program_header_entry_size)
                    .context("ELF hash program header offset overflow")?;
                image_offset = offset
                    .checked_add(le_u32(bytes, hash_program_header_offset as usize + 0x04)?)
                    .context("ELF image offset overflow")?;
                header_offset = image_offset
                    .checked_add(8)
                    .context("Qualcomm header offset overflow")?;
            } else if elf_class == 2 {
                let program_header_offset = offset
                    .checked_add(le_u32(bytes, offset as usize + 0x20)?)
                    .context("ELF program header offset overflow")?;
                let program_header_entry_size = le_u16(bytes, offset as usize + 0x36)? as u32;
                let hash_program_header_offset = program_header_offset
                    .checked_add(program_header_entry_size)
                    .context("ELF hash program header offset overflow")?;
                image_offset = offset
                    .checked_add(
                        u32::try_from(le_u64(bytes, hash_program_header_offset as usize + 0x08)?)
                            .context("ELF image offset does not fit in u32")?,
                    )
                    .context("ELF image offset overflow")?;
                header_offset = image_offset
                    .checked_add(8)
                    .context("Qualcomm header offset overflow")?;
            } else {
                bail!("unsupported ELF class {elf_class}");
            }
        } else if find_masked_pattern(
            bytes,
            offset as usize,
            LONG_QCOM_HEADER_PATTERN,
            LONG_QCOM_HEADER_MASK,
        )
        .is_none()
        {
            header_type = "short";
            header_offset = image_offset
                .checked_add(8)
                .context("Qualcomm header offset overflow")?;
        } else {
            header_type = "long";
            header_offset = image_offset
                .checked_add(LONG_QCOM_HEADER_PATTERN.len() as u32)
                .context("Qualcomm header offset overflow")?;
        }

        let header = header_offset as usize;
        let explicit_image_offset = le_u32(bytes, header)?;
        if explicit_image_offset != 0 {
            image_offset = explicit_image_offset;
        } else if header_type == "short" || header_type == "elf" {
            image_offset = image_offset
                .checked_add(0x28)
                .context("Qualcomm short image offset overflow")?;
        } else {
            image_offset = image_offset
                .checked_add(0x50)
                .context("Qualcomm long image offset overflow")?;
        }

        let image_address = le_u32(bytes, header + 0x04)?;
        let image_size = le_u32(bytes, header + 0x08)?;
        let code_size = le_u32(bytes, header + 0x0c)?;
        let signature_address = le_u32(bytes, header + 0x10)?;
        let signature_size = le_u32(bytes, header + 0x14)?;
        let certificates_address = le_u32(bytes, header + 0x18)?;
        let certificates_size = le_u32(bytes, header + 0x1c)?;
        let root_key_hash = extract_root_key_hash(bytes);

        Ok(Self {
            header_type,
            image_offset,
            header_offset,
            image_address,
            image_size,
            code_size,
            signature_address,
            signature_size,
            certificates_address,
            certificates_size,
            root_key_hash,
        })
    }
}

const LONG_QCOM_HEADER_PATTERN: &[u8] = &[
    0xd1, 0xdc, 0x4b, 0x84, 0x34, 0x10, 0xd7, 0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
];

const LONG_QCOM_HEADER_MASK: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[cfg(feature = "cli")]
pub fn read_qcom_source(path: &Path) -> Result<QcomSource> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("hex"))
    {
        return Ok(QcomSource {
            format: "intel-hex",
            bytes: parse_intel_hex(&bytes)
                .with_context(|| format!("failed to parse Intel HEX {}", path.display()))?,
        });
    }

    Ok(QcomSource {
        format: "raw",
        bytes,
    })
}

#[cfg(feature = "cli")]
pub fn read_qcom_candidates(path: &Path) -> Result<Vec<QcomCandidate>> {
    if path.is_dir() {
        let mut candidates = Vec::new();
        for entry in
            fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let source = read_qcom_source(&path)?;
                candidates.push(QcomCandidate {
                    name: path.display().to_string(),
                    format: source.format,
                    bytes: source.bytes,
                });
            }
        }
        return Ok(candidates);
    }

    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let mut archive = ZipArchive::new(Cursor::new(bytes))
            .with_context(|| format!("failed to open zip {}", path.display()))?;
        let mut candidates = Vec::new();

        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            if !file.is_file() {
                continue;
            }

            let name = file.name().to_string();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .with_context(|| format!("failed to read {name} from {}", path.display()))?;
            let (format, bytes) = if name
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("hex"))
            {
                ("intel-hex", parse_intel_hex(&bytes)?)
            } else {
                ("raw", bytes)
            };

            candidates.push(QcomCandidate {
                name,
                format,
                bytes,
            });
        }

        return Ok(candidates);
    }

    let source = read_qcom_source(path)?;
    Ok(vec![QcomCandidate {
        name: path.display().to_string(),
        format: source.format,
        bytes: source.bytes,
    }])
}

pub fn parse_intel_hex(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = core::str::from_utf8(bytes).context("Intel HEX is not valid UTF-8")?;
    let mut result = Vec::new();

    for (line_number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        ensure!(
            line.starts_with(':'),
            "Intel HEX line {} missing ':'",
            line_number + 1
        );
        let record = parse_hex_bytes(&line[1..])?;
        ensure!(
            record.len() >= 5,
            "Intel HEX line {} too short",
            line_number + 1
        );
        let byte_count = record[0] as usize;
        ensure!(
            record.len() == byte_count + 5,
            "Intel HEX line {} length mismatch",
            line_number + 1
        );

        if record[3] == 0 {
            result.extend_from_slice(&record[4..4 + byte_count]);
        }
    }

    Ok(result)
}

pub fn extract_root_key_hash(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut signatures = Vec::new();
    let mut last_offset = 0usize;

    for index in 0..bytes.len().saturating_sub(6) {
        let offset0 = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
        let offset1 = i16::from_be_bytes([bytes[index + 2], bytes[index + 3]]);
        let offset2 = u16::from_le_bytes([bytes[index + 4], bytes[index + 5]]);

        if offset0 == 0x8230 && offset1 >= 0 && offset2 == 0x8230 {
            let certificate_size = offset1 as usize + 4;
            if last_offset != 0 && last_offset != index {
                break;
            }
            let end = index.checked_add(certificate_size)?;
            let certificate = bytes.get(index..end)?;
            signatures.push(certificate.to_vec());
            last_offset = end;
        }
    }

    signatures.last().map(|root| Sha256::digest(root).to_vec())
}

#[cfg(feature = "cli")]
pub fn matching_armprg_loaders(path: &Path, rrkh: &[u8]) -> Result<Vec<MatchingLoader>> {
    ensure!(
        rrkh.len() == 0x20,
        "RRKH must be 32 bytes, got {}",
        rrkh.len()
    );
    let candidates = read_qcom_candidates(path)?;
    let mut matches = Vec::new();

    for candidate in candidates {
        if candidate.bytes.len() > 0x80000 {
            continue;
        }
        if !contains_utf16le(&candidate.bytes, "QHSUSB_ARMPRG") {
            continue;
        }
        let image = match QualcommImage::parse(&candidate.bytes, 0) {
            Ok(image) => image,
            Err(_) => continue,
        };
        let Some(root_key_hash) = image.root_key_hash else {
            continue;
        };
        if root_key_hash == rrkh {
            matches.push(MatchingLoader {
                name: candidate.name,
                format: candidate.format,
                size: candidate.bytes.len(),
                root_key_hash,
            });
        }
    }

    Ok(matches)
}

#[cfg(feature = "std")]
pub fn print_qcom_image(image: &QualcommImage) {
    println!("header type: {}", image.header_type);
    println!("image offset: 0x{:08x}", image.image_offset);
    println!("header offset: 0x{:08x}", image.header_offset);
    println!("image address: 0x{:08x}", image.image_address);
    println!("image size: {}", image.image_size);
    println!("code size: {}", image.code_size);
    println!("signature address: 0x{:08x}", image.signature_address);
    println!("signature size: {}", image.signature_size);
    println!("certificates address: 0x{:08x}", image.certificates_address);
    println!("certificates size: {}", image.certificates_size);
    if let Some(root_key_hash) = &image.root_key_hash {
        println!("root key hash: {}", hex_dump_compact(root_key_hash));
    } else {
        println!("root key hash: none");
    }
}

pub fn contains_utf16le(bytes: &[u8], needle: &str) -> bool {
    let encoded = needle
        .encode_utf16()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    find_bytes(bytes, &encoded).is_some()
}

fn find_masked_pattern(
    haystack: &[u8],
    offset: usize,
    pattern: &[u8],
    mask: &[u8],
) -> Option<usize> {
    if pattern.len() != mask.len() || offset >= haystack.len() || haystack.len() < pattern.len() {
        return None;
    }

    (offset..=haystack.len() - pattern.len()).find(|candidate| {
        pattern.iter().enumerate().all(|(index, expected)| {
            mask[index] == 0xff || haystack[candidate + index] == *expected
        })
    })
}
