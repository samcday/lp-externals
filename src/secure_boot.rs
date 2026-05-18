use std::io::Cursor;

use anyhow::{Context, Result, bail, ensure};
use hadris_fat::{FatFs, FatFsWriteExt};
use regf::{DataType, HiveBuilder, KeyTreeNode, KeyTreeValue, RegistryHive};
use sha1::{Digest as Sha1Digest, Sha1};

use crate::util::{parse_hex_bytes, write_le_u16};

const PATCH_DEFINITIONS_XML: &str = include_str!("../assets/wpinternals/PatchDefinitions.xml");
const PATCH_NAME_SPEC_A: &str = "SecureBootHack-V1.1-EFIESP";
const MOBILESTARTUP_PATH: &[&str] = &["Windows", "System32", "Boot", "mobilestartup.efi"];
const BCD_PATH: &[&str] = &["EFI", "Microsoft", "Boot", "BCD"];
const BCD_ALLOW_PRERELEASE_SIGNATURES: &str = "16000048";
const BCD_TARGET_OBJECTS: &[&str] = &[
    "{01de5a27-8705-40db-bad6-96fa5187d4a6}",
    "{7619dcc9-fafe-11d9-b411-000476eba25f}",
];

#[derive(Debug)]
pub(crate) struct EfiespPatchResult {
    pub(crate) mobilestartup_source: MobileStartupSource,
    pub(crate) mobilestartup_hash_before: String,
    pub(crate) mobilestartup_hash_after: String,
    pub(crate) bcd_changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MobileStartupSource {
    Stock,
    Donor,
    AlreadyPatched,
}

#[derive(Debug)]
pub(crate) enum MobileStartupPatchStatus {
    Supported { hash: String },
    AlreadyPatched { hash: String },
    Unsupported { hash: String },
}

impl MobileStartupSource {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Stock => "stock EFIESP",
            Self::Donor => "donor FFU",
            Self::AlreadyPatched => "already patched",
        }
    }
}

#[derive(Debug)]
enum PatchOutcome {
    Patched { before: String, after: String },
    AlreadyPatched { hash: String },
    Unsupported { hash: String },
}

#[derive(Clone, Debug)]
struct FilePatch {
    path: String,
    hash_original: String,
    hash_patched: String,
    patches: Vec<BytePatch>,
}

#[derive(Clone, Debug)]
struct BytePatch {
    address: usize,
    original: Vec<u8>,
    patched: Vec<u8>,
}

pub(crate) fn patch_spec_a_efiesp(
    efiesp: &mut [u8],
    donor_efiesp: Option<&[u8]>,
) -> Result<EfiespPatchResult> {
    validate_fat_image(efiesp).context("stock EFIESP FAT validation failed")?;

    let mut mobilestartup = read_fat_file(efiesp, MOBILESTARTUP_PATH)
        .context("failed to read EFIESP mobilestartup.efi")?;
    let first_outcome = apply_mobilestartup_patch(&mut mobilestartup)?;

    let (mobilestartup_source, mobilestartup_hash_before, mobilestartup_hash_after) =
        match first_outcome {
            PatchOutcome::Patched { before, after } => {
                write_fat_file(efiesp, MOBILESTARTUP_PATH, &mobilestartup)
                    .context("failed to write patched mobilestartup.efi")?;
                (MobileStartupSource::Stock, before, after)
            }
            PatchOutcome::AlreadyPatched { hash } => {
                (MobileStartupSource::AlreadyPatched, hash.clone(), hash)
            }
            PatchOutcome::Unsupported { hash: stock_hash } => {
                let donor_efiesp = donor_efiesp.with_context(|| {
                    format!(
                        "stock mobilestartup.efi hash {stock_hash} is not supported by {PATCH_NAME_SPEC_A}"
                    )
                })?;
                validate_fat_image(donor_efiesp).context("donor EFIESP FAT validation failed")?;
                let mut donor_mobilestartup = read_fat_file(donor_efiesp, MOBILESTARTUP_PATH)
                    .context("failed to read donor mobilestartup.efi")?;
                let donor_outcome = apply_mobilestartup_patch(&mut donor_mobilestartup)?;
                match donor_outcome {
                    PatchOutcome::Patched { before, after } => {
                        write_fat_file(efiesp, MOBILESTARTUP_PATH, &donor_mobilestartup)
                            .context("failed to write donor patched mobilestartup.efi")?;
                        (MobileStartupSource::Donor, before, after)
                    }
                    PatchOutcome::AlreadyPatched { hash } => {
                        write_fat_file(efiesp, MOBILESTARTUP_PATH, &donor_mobilestartup)
                            .context("failed to write donor patched mobilestartup.efi")?;
                        (MobileStartupSource::Donor, hash.clone(), hash)
                    }
                    PatchOutcome::Unsupported { hash } => bail!(
                        "donor mobilestartup.efi hash {hash} is not supported by {PATCH_NAME_SPEC_A}"
                    ),
                }
            }
        };

    let bcd = read_fat_file(efiesp, BCD_PATH).context("failed to read EFIESP BCD")?;
    let (patched_bcd, bcd_changed) = enable_bcd_test_signing(&bcd)?;
    if bcd_changed {
        write_fat_file(efiesp, BCD_PATH, &patched_bcd).context("failed to write patched BCD")?;
    }

    validate_fat_image(efiesp).context("patched EFIESP FAT validation failed")?;
    read_fat_file(efiesp, MOBILESTARTUP_PATH)
        .context("failed to re-read patched mobilestartup.efi")?;
    let final_bcd = read_fat_file(efiesp, BCD_PATH).context("failed to re-read patched BCD")?;
    validate_bcd_test_signing(&final_bcd)?;

    Ok(EfiespPatchResult {
        mobilestartup_source,
        mobilestartup_hash_before,
        mobilestartup_hash_after,
        bcd_changed,
    })
}

pub(crate) fn spec_a_mobilestartup_patch_status(efiesp: &[u8]) -> Result<MobileStartupPatchStatus> {
    validate_fat_image(efiesp).context("EFIESP FAT validation failed")?;
    let mut mobilestartup = read_fat_file(efiesp, MOBILESTARTUP_PATH)
        .context("failed to read EFIESP mobilestartup.efi")?;
    match apply_mobilestartup_patch(&mut mobilestartup)? {
        PatchOutcome::Patched { before, .. } => {
            Ok(MobileStartupPatchStatus::Supported { hash: before })
        }
        PatchOutcome::AlreadyPatched { hash } => {
            Ok(MobileStartupPatchStatus::AlreadyPatched { hash })
        }
        PatchOutcome::Unsupported { hash } => Ok(MobileStartupPatchStatus::Unsupported { hash }),
    }
}

pub(crate) fn build_spec_a_efiesp_payloads(
    stock_efiesp: &[u8],
    patched_efiesp: &[u8],
    efiesp_sector_count: u64,
) -> Result<(Vec<u8>, u64, Vec<u8>)> {
    ensure!(
        stock_efiesp.len() == patched_efiesp.len(),
        "patched EFIESP size changed from {} to {} bytes",
        stock_efiesp.len(),
        patched_efiesp.len()
    );
    ensure!(
        patched_efiesp.len().is_multiple_of(0x200),
        "EFIESP image is not sector-aligned"
    );
    ensure!(
        patched_efiesp.len() / 0x200 == efiesp_sector_count as usize,
        "EFIESP image sector count {} does not match GPT sector count {efiesp_sector_count}",
        patched_efiesp.len() / 0x200
    );

    let reserved_original = u16::from_le_bytes(
        stock_efiesp
            .get(0x0e..0x10)
            .context("EFIESP BPB reserved-sector field is missing")?
            .try_into()
            .unwrap(),
    ) as u64;
    ensure!(reserved_original != 0, "EFIESP has zero reserved sectors");
    ensure!(
        reserved_original <= efiesp_sector_count,
        "EFIESP reserved sectors exceed partition size"
    );

    let half_sector_count = efiesp_sector_count / 2;
    ensure!(
        half_sector_count >= reserved_original,
        "EFIESP partition is too small for Spec A split payload"
    );
    let allocated_sector_count = half_sector_count - reserved_original + 1;
    let reserved_new = allocated_sector_count.min(u16::MAX as u64);
    ensure!(
        reserved_new <= u16::MAX as u64,
        "reserved sector count overflow"
    );

    let first_len = usize::try_from(reserved_original)
        .context("reserved-sector count does not fit in usize")?
        .checked_mul(0x200)
        .context("first EFIESP payload length overflow")?;
    let second_offset = first_len;
    let second_len = patched_efiesp
        .len()
        .checked_sub(
            usize::try_from(reserved_new)
                .context("new reserved-sector count does not fit in usize")?
                .checked_mul(0x200)
                .context("new reserved-sector byte count overflow")?,
        )
        .context("new reserved-sector byte count exceeds EFIESP size")?;
    ensure!(
        second_len.is_multiple_of(0x200),
        "second EFIESP payload is not sector-aligned"
    );

    let mut first = stock_efiesp[..first_len].to_vec();
    write_le_u16(&mut first, 0x0e, reserved_new as u16)?;
    let second = patched_efiesp[second_offset..second_offset + second_len].to_vec();

    Ok((first, reserved_new, second))
}

fn apply_mobilestartup_patch(mobilestartup: &mut [u8]) -> Result<PatchOutcome> {
    let hash_before = sha1_hex(mobilestartup);
    let definitions = parse_patch_definitions(PATCH_NAME_SPEC_A)?;
    let matching_patched = definitions.iter().find(|definition| {
        definition.hash_patched.eq_ignore_ascii_case(&hash_before)
            && path_matches_mobilestartup(&definition.path)
    });
    if matching_patched.is_some() {
        return Ok(PatchOutcome::AlreadyPatched { hash: hash_before });
    }

    let Some(definition) = definitions.iter().find(|definition| {
        definition.hash_original.eq_ignore_ascii_case(&hash_before)
            && path_matches_mobilestartup(&definition.path)
    }) else {
        return Ok(PatchOutcome::Unsupported { hash: hash_before });
    };

    for patch in &definition.patches {
        let end = patch
            .address
            .checked_add(patch.original.len())
            .context("mobilestartup patch range overflow")?;
        ensure!(
            end <= mobilestartup.len(),
            "mobilestartup patch at 0x{:x} exceeds file length {}",
            patch.address,
            mobilestartup.len()
        );
        ensure!(
            mobilestartup[patch.address..end] == patch.original,
            "mobilestartup original bytes mismatch at 0x{:x}",
            patch.address
        );
        ensure!(
            patch.original.len() == patch.patched.len(),
            "mobilestartup patch at 0x{:x} changes byte length",
            patch.address
        );
        mobilestartup[patch.address..end].copy_from_slice(&patch.patched);
    }

    let hash_after = sha1_hex(mobilestartup);
    ensure!(
        definition.hash_patched.eq_ignore_ascii_case(&hash_after),
        "patched mobilestartup hash {hash_after} did not match expected {}",
        definition.hash_patched
    );

    Ok(PatchOutcome::Patched {
        before: hash_before,
        after: hash_after,
    })
}

fn parse_patch_definitions(name: &str) -> Result<Vec<FilePatch>> {
    let doc = roxmltree::Document::parse(PATCH_DEFINITIONS_XML)
        .context("failed to parse vendored PatchDefinitions.xml")?;
    let definition = doc
        .descendants()
        .find(|node| node.has_tag_name("PatchDefinition") && node.attribute("Name") == Some(name))
        .with_context(|| format!("vendored PatchDefinitions.xml does not contain {name}"))?;

    definition
        .descendants()
        .filter(|node| node.has_tag_name("TargetFile"))
        .map(|target| {
            let path = target
                .attribute("Path")
                .context("TargetFile missing Path")?
                .to_string();
            let hash_original = target
                .attribute("HashOriginal")
                .context("TargetFile missing HashOriginal")?
                .to_string();
            let hash_patched = target
                .attribute("HashPatched")
                .context("TargetFile missing HashPatched")?
                .to_string();
            let patches = target
                .descendants()
                .filter(|node| node.has_tag_name("Patch"))
                .map(|patch| {
                    let address = parse_patch_address(
                        patch
                            .attribute("Address")
                            .context("Patch missing Address")?,
                    )?;
                    let original = parse_hex_bytes(
                        patch
                            .attribute("OriginalBytes")
                            .context("Patch missing OriginalBytes")?,
                    )?;
                    let patched = parse_hex_bytes(
                        patch
                            .attribute("PatchedBytes")
                            .context("Patch missing PatchedBytes")?,
                    )?;
                    Ok(BytePatch {
                        address,
                        original,
                        patched,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(FilePatch {
                path,
                hash_original,
                hash_patched,
                patches,
            })
        })
        .collect()
}

fn parse_patch_address(value: &str) -> Result<usize> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    usize::from_str_radix(value, 16).with_context(|| format!("invalid patch address {value}"))
}

fn path_matches_mobilestartup(path: &str) -> bool {
    path.replace('\\', "/")
        .eq_ignore_ascii_case("Windows/System32/Boot/mobilestartup.efi")
}

fn read_fat_file(image: &[u8], path: &[&str]) -> Result<Vec<u8>> {
    ensure!(!path.is_empty(), "empty FAT path");
    let cursor = Cursor::new(image);
    let fs = FatFs::open(cursor).context("failed to open FAT image")?;
    let mut dir = fs.root_dir();
    for component in &path[..path.len() - 1] {
        dir = dir
            .open_dir(component)
            .with_context(|| format!("failed to open FAT directory {component}"))?;
    }

    let mut reader = dir
        .open_file(path[path.len() - 1])
        .with_context(|| format!("failed to open FAT file {}", path.join("/")))?
        .with_cached_chain()
        .context("failed to cache FAT cluster chain")?;
    let mut bytes = vec![0; reader.size()];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let read = reader
            .read(&mut bytes[offset..])
            .context("failed to read FAT file")?;
        ensure!(read != 0, "short FAT file read");
        offset += read;
    }
    Ok(bytes)
}

fn write_fat_file(image: &mut [u8], path: &[&str], bytes: &[u8]) -> Result<()> {
    ensure!(!path.is_empty(), "empty FAT path");
    let cursor = Cursor::new(image);
    let fs = FatFs::open(cursor).context("failed to open FAT image for writing")?;
    let mut dir = fs.root_dir();
    for component in &path[..path.len() - 1] {
        dir = dir
            .open_dir(component)
            .with_context(|| format!("failed to open FAT directory {component}"))?;
    }

    let filename = path[path.len() - 1];
    let entry = dir
        .find(filename)
        .with_context(|| format!("failed to find FAT file {}", path.join("/")))?
        .with_context(|| format!("FAT file {} is missing", path.join("/")))?;
    fs.truncate(&entry, 0)
        .with_context(|| format!("failed to truncate FAT file {}", path.join("/")))?;
    let entry = dir
        .find(filename)
        .with_context(|| format!("failed to re-find FAT file {}", path.join("/")))?
        .with_context(|| format!("FAT file {} disappeared after truncate", path.join("/")))?;
    let mut writer = fs
        .write_file(&entry)
        .with_context(|| format!("failed to open FAT writer for {}", path.join("/")))?;
    let written = writer
        .write(bytes)
        .with_context(|| format!("failed to write FAT file {}", path.join("/")))?;
    ensure!(written == bytes.len(), "short FAT file write");
    writer
        .finish()
        .with_context(|| format!("failed to finalize FAT file {}", path.join("/")))?;
    Ok(())
}

fn validate_fat_image(image: &[u8]) -> Result<()> {
    let cursor = Cursor::new(image);
    let fs = FatFs::open(cursor).context("failed to open FAT image")?;
    fs.root_dir();
    Ok(())
}

fn enable_bcd_test_signing(bcd: &[u8]) -> Result<(Vec<u8>, bool)> {
    let hive = RegistryHive::from_bytes(bcd.to_vec()).context("failed to parse BCD hive")?;
    let (major, minor) = hive.version();
    let root = hive.root_key().context("failed to read BCD root key")?;
    let mut tree = key_to_tree(&root)?;
    let mut changed = false;

    for object in BCD_TARGET_OBJECTS {
        let elements =
            get_or_create_path(&mut tree, &["Objects", object, "Elements"], &mut changed);
        let element = get_or_create_child(elements, BCD_ALLOW_PRERELEASE_SIGNATURES, &mut changed);
        match element
            .values
            .iter_mut()
            .find(|value| value.name.eq_ignore_ascii_case("Element"))
        {
            Some(value) => {
                if value.data_type != DataType::Binary || value.data != [1] {
                    value.data_type = DataType::Binary;
                    value.data = vec![1];
                    changed = true;
                }
            }
            None => {
                element.values.push(KeyTreeValue {
                    name: "Element".to_string(),
                    data_type: DataType::Binary,
                    data: vec![1],
                });
                changed = true;
            }
        }
    }

    if !changed {
        validate_bcd_test_signing(bcd)?;
        return Ok((bcd.to_vec(), false));
    }

    let mut builder = HiveBuilder::from_tree_with_version(tree, major, minor);
    let rebuilt = builder.to_bytes().context("failed to rebuild BCD hive")?;
    validate_bcd_test_signing(&rebuilt)?;
    Ok((rebuilt, true))
}

fn validate_bcd_test_signing(bcd: &[u8]) -> Result<()> {
    let hive = RegistryHive::from_bytes(bcd.to_vec()).context("failed to parse BCD hive")?;
    for object in BCD_TARGET_OBJECTS {
        let key_path = format!(
            "Objects\\{}\\Elements\\{}",
            object, BCD_ALLOW_PRERELEASE_SIGNATURES
        );
        let key = hive
            .open_key(&key_path)
            .with_context(|| format!("BCD key {key_path} is missing"))?;
        let value = key
            .value("Element")
            .with_context(|| format!("BCD key {key_path} has no Element value"))?;
        ensure!(
            value.data_type() == DataType::Binary,
            "BCD {key_path} Element is not REG_BINARY"
        );
        ensure!(
            value.raw_data()? == [1],
            "BCD {key_path} Element is not boolean true"
        );
    }
    Ok(())
}

fn key_to_tree(key: &regf::hive::RegistryKey<'_>) -> Result<KeyTreeNode> {
    let mut node = KeyTreeNode::new(&key.name());
    for value in key.values()? {
        node.values.push(KeyTreeValue {
            name: value.name(),
            data_type: value.data_type(),
            data: value.raw_data()?,
        });
    }
    for subkey in key.subkeys()? {
        node.children.push(key_to_tree(&subkey)?);
    }
    Ok(node)
}

fn get_or_create_path<'a>(
    node: &'a mut KeyTreeNode,
    path: &[&str],
    changed: &mut bool,
) -> &'a mut KeyTreeNode {
    let mut current = node;
    for component in path {
        current = get_or_create_child(current, component, changed);
    }
    current
}

fn get_or_create_child<'a>(
    node: &'a mut KeyTreeNode,
    name: &str,
    changed: &mut bool,
) -> &'a mut KeyTreeNode {
    if let Some(index) = node
        .children
        .iter()
        .position(|child| child.name.eq_ignore_ascii_case(name))
    {
        return &mut node.children[index];
    }

    node.children.push(KeyTreeNode::new(name));
    *changed = true;
    node.children.last_mut().unwrap()
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_a_patch_definitions() {
        let definitions = parse_patch_definitions(PATCH_NAME_SPEC_A).unwrap();
        assert!(definitions.iter().any(|definition| {
            path_matches_mobilestartup(&definition.path) && !definition.patches.is_empty()
        }));
    }
}
