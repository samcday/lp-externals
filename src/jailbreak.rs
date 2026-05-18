use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow, ensure};

use crate::{
    ffu::FfuMetadata,
    gpt::{GptPartition, ParsedGpt, insert_spec_a_hack},
    qcom::QualcommImage,
    util::{
        align, checksum8, checksum16_le, decode_utf16_name, find_bytes, find_unique_masked_pattern,
        le_u16, le_u24, le_u32, write_le_u16, write_le_u24, write_le_u32,
    },
};

const SECTOR_SIZE: u64 = 0x200;
const GPT_EDL_WRITE_LEN: u64 = 0x41ff;
const WINSECAPP_EDL_LIMIT: u64 = 0x1e7fe00;

pub(crate) struct JailbreakArtifacts {
    pub(crate) write_plan: Vec<WritePlanEntry>,
    pub(crate) patched_gpt: Vec<u8>,
    pub(crate) hack_sector: Vec<u8>,
    pub(crate) patched_sbl2: Vec<u8>,
    pub(crate) patched_sbl3: Vec<u8>,
    pub(crate) patched_uefi: Vec<u8>,
}

pub(crate) struct WritePlanEntry {
    pub(crate) name: &'static str,
    pub(crate) start_sector: u64,
    pub(crate) byte_len: u64,
    pub(crate) source: &'static str,
    pub(crate) operation: &'static str,
}

pub(crate) fn build_jailbreak_artifacts(
    ffu_path: &Path,
    ffu: &FfuMetadata,
    engineering_sbl3_path: &Path,
) -> Result<JailbreakArtifacts> {
    let gpt = ffu.get_sectors(ffu_path, 1, 0x21)?;
    let patched_gpt = insert_spec_a_hack(&gpt).context("failed to insert Spec A GPT hack")?;
    let patched_partitions = ParsedGpt::parse(&patched_gpt)?;

    let sbl1 = ffu.get_partition(ffu_path, "SBL1")?;
    let stock_sbl2 = ffu.get_partition(ffu_path, "SBL2")?;
    let patched_sbl2 = patch_sbl2(stock_sbl2).context("failed to patch SBL2")?;
    let hack_sector = generate_hack_sector(&sbl1, &patched_sbl2)
        .context("failed to generate Spec A HACK sector")?;

    let stock_sbl3 = ffu.get_partition(ffu_path, "SBL3")?;
    let engineering_sbl3 = fs::read(engineering_sbl3_path)
        .with_context(|| format!("failed to read {}", engineering_sbl3_path.display()))?;
    ensure!(
        !engineering_sbl3.is_empty(),
        "engineering SBL3 {} is empty",
        engineering_sbl3_path.display()
    );
    ensure!(
        engineering_sbl3.len() <= stock_sbl3.len(),
        "engineering SBL3 is too large: {} bytes > stock partition {} bytes",
        engineering_sbl3.len(),
        stock_sbl3.len()
    );
    let patched_sbl3 = patch_sbl3(engineering_sbl3).context("failed to patch SBL3")?;

    let stock_uefi = ffu.get_partition(ffu_path, "UEFI")?;
    let patched_uefi = patch_uefi(stock_uefi).context("failed to patch UEFI")?;

    ensure_fits(&patched_partitions, "HACK", hack_sector.len())?;
    ensure_fits(&patched_partitions, "SBL2", patched_sbl2.len())?;
    ensure_fits(&patched_partitions, "SBL3", patched_sbl3.len())?;
    ensure_fits(&patched_partitions, "UEFI", patched_uefi.len())?;

    let sbl1_partition = partition(&patched_partitions, "SBL1")?;
    let tz_partition = partition(&patched_partitions, "TZ")?;
    let rpm_partition = partition(&patched_partitions, "RPM")?;
    let winsecapp_partition = partition(&patched_partitions, "WINSECAPP")?;

    let sbl1_write_sectors = sbl1_partition
        .sector_count()
        .checked_sub(1)
        .context("patched SBL1 partition is too small for WPinternals partial write")?;
    let sbl1_write_len = sbl1_write_sectors
        .checked_mul(SECTOR_SIZE)
        .context("SBL1 write length overflow")?;
    ensure!(
        sbl1_write_len <= sbl1.len() as u64,
        "planned SBL1 write exceeds stock SBL1 bytes"
    );

    let winsecapp_start = winsecapp_partition
        .first_lba
        .checked_mul(SECTOR_SIZE)
        .context("WINSECAPP byte offset overflow")?;
    ensure!(
        winsecapp_start < WINSECAPP_EDL_LIMIT,
        "WINSECAPP starts beyond ARMPRG write limit"
    );
    let stock_winsecapp_len = ffu.get_partition(ffu_path, "WINSECAPP")?.len() as u64;
    let winsecapp_len = if winsecapp_start + stock_winsecapp_len > WINSECAPP_EDL_LIMIT {
        WINSECAPP_EDL_LIMIT - winsecapp_start
    } else {
        stock_winsecapp_len
    };

    let write_plan = vec![
        WritePlanEntry {
            name: "MBR",
            start_sector: 0,
            byte_len: SECTOR_SIZE,
            source: "stock FFU sector 0",
            operation: "copy",
        },
        WritePlanEntry {
            name: "GPT",
            start_sector: 1,
            byte_len: GPT_EDL_WRITE_LEN,
            source: "patched primary GPT",
            operation: "patch",
        },
        WritePlanEntry {
            name: "HACK",
            start_sector: partition(&patched_partitions, "HACK")?.first_lba,
            byte_len: hack_sector.len() as u64,
            source: "generated from SBL1/SBL2",
            operation: "generate",
        },
        WritePlanEntry {
            name: "SBL2",
            start_sector: partition(&patched_partitions, "SBL2")?.first_lba,
            byte_len: patched_sbl2.len() as u64,
            source: "stock FFU SBL2",
            operation: "patch",
        },
        WritePlanEntry {
            name: "SBL3",
            start_sector: partition(&patched_partitions, "SBL3")?.first_lba,
            byte_len: patched_sbl3.len() as u64,
            source: "engineering SBL3",
            operation: "patch",
        },
        WritePlanEntry {
            name: "UEFI",
            start_sector: partition(&patched_partitions, "UEFI")?.first_lba,
            byte_len: patched_uefi.len() as u64,
            source: "stock FFU UEFI",
            operation: "patch",
        },
        WritePlanEntry {
            name: "SBL1",
            start_sector: sbl1_partition.first_lba,
            byte_len: sbl1_write_len,
            source: "stock FFU SBL1",
            operation: "partial copy",
        },
        WritePlanEntry {
            name: "TZ",
            start_sector: tz_partition.first_lba,
            byte_len: ffu.get_partition(ffu_path, "TZ")?.len() as u64,
            source: "stock FFU TZ",
            operation: "copy",
        },
        WritePlanEntry {
            name: "RPM",
            start_sector: rpm_partition.first_lba,
            byte_len: ffu.get_partition(ffu_path, "RPM")?.len() as u64,
            source: "stock FFU RPM",
            operation: "copy",
        },
        WritePlanEntry {
            name: "WINSECAPP",
            start_sector: winsecapp_partition.first_lba,
            byte_len: winsecapp_len,
            source: "stock FFU WINSECAPP",
            operation: "bounded copy",
        },
    ];

    validate_write_plan(&write_plan)?;

    Ok(JailbreakArtifacts {
        write_plan,
        patched_gpt,
        hack_sector,
        patched_sbl2,
        patched_sbl3,
        patched_uefi,
    })
}

fn patch_sbl2(mut sbl2: Vec<u8>) -> Result<Vec<u8>> {
    let offset = find_unique_masked_pattern(
        &sbl2,
        &[
            0xff, 0xff, 0xff, 0xe3, 0x01, 0x0e, 0x42, 0xe3, 0x28, 0x00, 0xd0, 0xe5, 0x1e, 0xff,
            0x2f, 0xe1,
        ],
        Some(&[
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]),
        "SBL2 security check",
    )?;
    sbl2[offset + 8..offset + 12].copy_from_slice(&[0x00, 0x00, 0xa0, 0xe3]);
    Ok(sbl2)
}

fn patch_sbl3(mut sbl3: Vec<u8>) -> Result<Vec<u8>> {
    let offset = find_unique_masked_pattern(
        &sbl3,
        &[
            0x04, 0x00, 0x9f, 0xe5, 0x28, 0x00, 0xd0, 0xe5, 0x1e, 0xff, 0x2f, 0xe1,
        ],
        None,
        "SBL3 security check",
    )?;
    sbl3[offset + 4..offset + 8].copy_from_slice(&[0x00, 0x00, 0xa0, 0xe3]);
    Ok(sbl3)
}

fn generate_hack_sector(sbl1: &[u8], patched_sbl2: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        patched_sbl2.len() >= 0x0c,
        "SBL2 is too short for HACK sector header"
    );
    let qcom =
        QualcommImage::parse(sbl1, 0x2800).context("failed to parse SBL1 Qualcomm header")?;

    let partition_loader_table_offset = find_unique_masked_pattern(
        sbl1,
        &[
            0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        None,
        "SBL1 partition-loader table",
    )?;

    let shared_memory_offset = find_unique_masked_pattern(
        sbl1,
        &[
            0x04, 0x00, 0x9f, 0xe5, 0x28, 0x00, 0xd0, 0xe5, 0x1e, 0xff, 0x2f, 0xe1, 0xff, 0xff,
            0xff, 0xff,
        ],
        Some(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff,
        ]),
        "SBL1 shared-memory security flag",
    )?;
    let shared_memory_address = le_u32(sbl1, shared_memory_offset + 0x0c)?;
    let global_is_security_enabled_address = shared_memory_address
        .checked_add(0x28)
        .context("SBL1 global security flag address overflow")?;

    let return_offset = find_unique_masked_pattern(
        sbl1,
        &[
            0x01, 0xff, 0xa0, 0xe3, 0xff, 0xff, 0xa0, 0xe1, 0x1c, 0xd0, 0x8d, 0xe2, 0xf0, 0x4f,
            0xbd, 0xe8, 0x1e, 0xff, 0x2f, 0xe1,
        ],
        Some(&[
            0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]),
        "SBL1 return path",
    )?;
    let return_address = (return_offset as u32)
        .checked_sub(qcom.image_offset)
        .and_then(|offset| offset.checked_add(qcom.image_address))
        .context("SBL1 return address overflow")?;

    ensure!(
        partition_loader_table_offset + 0xa0 <= sbl1.len(),
        "SBL1 partition-loader table is truncated"
    );

    let mut sector = vec![0; 0x200];
    let content = [
        0x16, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x28, 0xbd, 0x02,
        0x00, 0xd8, 0x01, 0x00, 0x00, 0xd8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xe3, 0x3c,
        0x10, 0x9f, 0xe5, 0x00, 0x00, 0xc1, 0xe5, 0x38, 0x00, 0x9f, 0xe5, 0x38, 0x10, 0x9f, 0xe5,
        0x00, 0x00, 0x81, 0xe5, 0x34, 0x10, 0x9f, 0xe5, 0x00, 0x00, 0x81, 0xe5, 0x30, 0x00, 0x9f,
        0xe5, 0x20, 0x10, 0x9f, 0xe5, 0x2c, 0x30, 0x9f, 0xe5, 0x00, 0x20, 0x90, 0xe5, 0x00, 0x20,
        0x81, 0xe5, 0x04, 0x00, 0x80, 0xe2, 0x04, 0x10, 0x81, 0xe2, 0x03, 0x00, 0x50, 0xe1, 0xf9,
        0xff, 0xff, 0xba, 0x14, 0xf0, 0x9f, 0xe5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00,
        0x90, 0xbf, 0x02, 0x00, 0xd0, 0xbf, 0x02, 0x00, 0xa0, 0xbd, 0x02, 0x00, 0xa0, 0xbe, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    sector[..content.len()].copy_from_slice(&content);
    sector[..0x0c].copy_from_slice(&patched_sbl2[..0x0c]);
    write_le_u32(&mut sector, 0x70, global_is_security_enabled_address)?;
    write_le_u32(&mut sector, 0x88, return_address)?;
    sector[0xa0..0xf0].copy_from_slice(
        &sbl1[partition_loader_table_offset..partition_loader_table_offset + 0x50],
    );
    write_le_u32(&mut sector, 0xa0 + 0x30, 0)?;
    sector[0xf0..0x140].copy_from_slice(
        &sbl1[partition_loader_table_offset..partition_loader_table_offset + 0x50],
    );
    write_le_u32(&mut sector, 0xf0 + 0x2c, 0)?;
    write_le_u32(&mut sector, 0xf0 + 0x38, 0x210f0)?;
    sector[0x190..0x1a0].fill(0x74);
    write_le_u32(&mut sector, 0x1fc, 0x0002bd28)?;
    Ok(sector)
}

fn patch_uefi(uefi: Vec<u8>) -> Result<Vec<u8>> {
    let mut image = ParsedUefi::parse(uefi)?;
    image.patch()?;
    image.rebuild()
}

struct ParsedUefi {
    binary: Vec<u8>,
    decompressed: Vec<u8>,
    files: Vec<EfiFile>,
    padding_byte: u8,
    volume_header_offset: usize,
    volume_size: usize,
    file_header_offset: usize,
    section_header_offset: usize,
    compressed_subimage_offset: usize,
    compressed_subimage_size: usize,
}

#[derive(Clone)]
struct EfiFile {
    name: String,
    file_offset: usize,
    binary_offset: usize,
    size: usize,
}

impl ParsedUefi {
    fn parse(binary: Vec<u8>) -> Result<Self> {
        let fvh_offset = find_bytes(&binary, b"_FVH").context("UEFI volume header not found")?;
        let volume_header_offset = fvh_offset
            .checked_sub(0x28)
            .context("UEFI volume header offset underflow")?;
        ensure!(
            verify_volume_checksum(&binary, volume_header_offset)?,
            "UEFI volume checksum mismatch"
        );
        let volume_size = le_u32(&binary, volume_header_offset + 0x20)? as usize;
        let volume_header_size = le_u16(&binary, volume_header_offset + 0x30)? as usize;
        let padding_byte = if le_u32(&binary, volume_header_offset + 0x2c)? & 0x00000800 != 0 {
            0xff
        } else {
            0x00
        };

        let mut file_header_offset = volume_header_offset + volume_header_size;
        let mut outer_file_size;
        loop {
            ensure!(
                file_header_offset + 0x18 <= binary.len(),
                "UEFI file header truncated"
            );
            ensure!(
                verify_file_checksum(&binary, file_header_offset)?,
                "UEFI file checksum mismatch"
            );
            outer_file_size = le_u24(&binary, file_header_offset + 0x14)? as usize;
            if binary[file_header_offset + 0x12] == 0x0b {
                break;
            }
            file_header_offset = align(
                volume_header_offset + volume_header_size,
                file_header_offset + outer_file_size,
                8,
            );
            ensure!(
                file_header_offset < volume_header_offset + volume_size,
                "UEFI firmware volume image file not found"
            );
        }

        let mut section_header_offset = file_header_offset + 0x18;
        let mut section_size;
        loop {
            ensure!(
                section_header_offset + 0x18 <= binary.len(),
                "UEFI section header truncated"
            );
            section_size = le_u24(&binary, section_header_offset)? as usize;
            if binary[section_header_offset + 0x03] == 0x02 {
                break;
            }
            section_header_offset = align(
                file_header_offset + 0x18,
                section_header_offset + section_size,
                4,
            );
            ensure!(
                section_header_offset < file_header_offset + outer_file_size,
                "UEFI GUID-defined section not found"
            );
        }

        let section_header_size = le_u16(&binary, section_header_offset + 0x14)? as usize;
        let compressed_subimage_offset = section_header_offset + section_header_size;
        let compressed_subimage_size = section_size
            .checked_sub(section_header_size)
            .context("UEFI compressed section size underflow")?;
        let compressed = binary
            .get(compressed_subimage_offset..compressed_subimage_offset + compressed_subimage_size)
            .context("UEFI compressed section truncated")?;
        let mut decompressed = Vec::new();
        lzma_rs::lzma_decompress(&mut Cursor::new(compressed), &mut decompressed)
            .context("failed to decompress UEFI LZMA subimage")?;

        let mut decompressed_section_offset = 0usize;
        loop {
            ensure!(
                decompressed_section_offset + 0x18 <= decompressed.len(),
                "UEFI decompressed section header truncated"
            );
            if decompressed[decompressed_section_offset + 0x03] == 0x17 {
                break;
            }
            let size = le_u24(&decompressed, decompressed_section_offset)? as usize;
            decompressed_section_offset = align(0, decompressed_section_offset + size, 4);
            ensure!(
                decompressed_section_offset < decompressed.len(),
                "UEFI decompressed firmware volume section not found"
            );
        }

        let decompressed_volume_header_offset = decompressed_section_offset + 4;
        ensure!(
            decompressed.get(
                decompressed_volume_header_offset + 0x28..decompressed_volume_header_offset + 0x2c
            ) == Some(b"_FVH"),
            "UEFI decompressed volume header magic missing"
        );
        ensure!(
            verify_volume_checksum(&decompressed, decompressed_volume_header_offset)?,
            "UEFI decompressed volume checksum mismatch"
        );
        let decompressed_volume_size =
            le_u32(&decompressed, decompressed_volume_header_offset + 0x20)? as usize;
        let decompressed_volume_header_size =
            le_u16(&decompressed, decompressed_volume_header_offset + 0x30)? as usize;
        let mut decompressed_file_offset =
            decompressed_volume_header_offset + decompressed_volume_header_size;
        let mut files = Vec::new();

        while decompressed_file_offset + 0x18
            < decompressed_volume_header_offset + decompressed_volume_size
        {
            if decompressed[decompressed_file_offset..decompressed_file_offset + 0x18]
                .iter()
                .all(|byte| *byte == padding_byte)
            {
                break;
            }
            let file_size = le_u24(&decompressed, decompressed_file_offset + 0x14)? as usize;
            if decompressed_file_offset + file_size
                >= decompressed_volume_header_offset + decompressed_volume_size
            {
                break;
            }
            ensure!(
                verify_file_checksum(&decompressed, decompressed_file_offset)?,
                "UEFI decompressed file checksum mismatch"
            );

            let mut section_offset = decompressed_file_offset + 0x18;
            let mut name = None;
            let mut binary_offset = None;
            let mut binary_size = None;
            while section_offset < decompressed_file_offset + file_size {
                let section_size = le_u24(&decompressed, section_offset)? as usize;
                let section_type = decompressed[section_offset + 0x03];
                if section_type == 0x15 {
                    name = Some(
                        decode_utf16_name(
                            &decompressed[section_offset + 0x04..section_offset + section_size],
                        )
                        .trim_matches(['\0', ' '])
                        .to_string(),
                    );
                } else if section_type == 0x10 || section_type == 0x19 {
                    binary_offset = Some(section_offset + 0x04);
                    binary_size = Some(section_size - 0x04);
                }
                section_offset = align(
                    decompressed_file_offset + 0x18,
                    section_offset + section_size,
                    4,
                );
            }

            if let (Some(name), Some(binary_offset), Some(size)) =
                (name, binary_offset, binary_size)
            {
                files.push(EfiFile {
                    name,
                    file_offset: decompressed_file_offset,
                    binary_offset,
                    size,
                });
            }

            decompressed_file_offset = align(
                decompressed_volume_header_offset + decompressed_volume_header_size,
                decompressed_file_offset + file_size,
                8,
            );
        }

        Ok(Self {
            binary,
            decompressed,
            files,
            padding_byte,
            volume_header_offset,
            volume_size,
            file_header_offset,
            section_header_offset,
            compressed_subimage_offset,
            compressed_subimage_size,
        })
    }

    fn patch(&mut self) -> Result<()> {
        let security_dxe = self.file("SecurityDxe")?.clone();
        self.clear_pe_checksum(&security_dxe)?;
        let offset = find_unique_masked_pattern(
            &self.decompressed
                [security_dxe.binary_offset..security_dxe.binary_offset + security_dxe.size],
            &[
                0xf0, 0x41, 0x2d, 0xe9, 0xff, 0xff, 0xb0, 0xe1, 0x28, 0xd0, 0x4d, 0xe2, 0xff, 0xff,
                0xa0, 0xe1, 0x00, 0x00, 0xff, 0x13, 0x20, 0xff, 0xa0, 0xe3,
            ],
            Some(&[
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00,
            ]),
            "SecurityDxe patch",
        )?;
        self.decompressed
            [security_dxe.binary_offset + offset..security_dxe.binary_offset + offset + 8]
            .copy_from_slice(&[0x00, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1]);
        calculate_file_checksum(&mut self.decompressed, security_dxe.file_offset)?;

        let security_services = self.file("SecurityServicesDxe")?.clone();
        self.clear_pe_checksum(&security_services)?;
        let first = find_unique_masked_pattern(
            &self.decompressed[security_services.binary_offset
                ..security_services.binary_offset + security_services.size],
            &[
                0x10, 0xff, 0xff, 0xe5, 0x80, 0xff, 0x10, 0xe3, 0xff, 0xff, 0xff, 0x0a,
            ],
            Some(&[
                0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00,
            ]),
            "SecurityServicesDxe first branch",
        )?;
        self.decompressed[security_services.binary_offset + first + 0x0b] = 0xea;
        let second = find_unique_masked_pattern(
            &self.decompressed[security_services.binary_offset
                ..security_services.binary_offset + security_services.size],
            &[
                0x11, 0xff, 0xff, 0xe5, 0x40, 0xff, 0x10, 0xe3, 0xff, 0xff, 0xff, 0x0a,
            ],
            Some(&[
                0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00,
            ]),
            "SecurityServicesDxe second branch",
        )?;
        self.decompressed[security_services.binary_offset + second + 0x0b] = 0xea;
        calculate_file_checksum(&mut self.decompressed, security_services.file_offset)?;

        let decompressed_volume_header_offset = find_bytes(&self.decompressed, b"_FVH")
            .and_then(|offset| offset.checked_sub(0x28))
            .context("failed to rediscover decompressed UEFI volume header")?;
        calculate_volume_checksum(&mut self.decompressed, decompressed_volume_header_offset)?;
        Ok(())
    }

    fn rebuild(mut self) -> Result<Vec<u8>> {
        let compressed = compress_lzma_alone(&self.decompressed)
            .context("failed to recompress UEFI LZMA subimage")?;

        let mut rebuilt = vec![0; self.binary.len()];
        rebuilt[..self.compressed_subimage_offset]
            .copy_from_slice(&self.binary[..self.compressed_subimage_offset]);
        let complete_image_size = le_u32(&rebuilt, 0x14)?;
        write_le_u32(&mut rebuilt, 0x10, complete_image_size)?;
        write_le_u32(&mut rebuilt, 0x18, 0)?;
        write_le_u32(&mut rebuilt, 0x1c, 0)?;
        write_le_u32(&mut rebuilt, 0x20, 0)?;
        write_le_u32(&mut rebuilt, 0x24, 0)?;

        ensure!(
            self.compressed_subimage_offset + compressed.len() <= rebuilt.len(),
            "recompressed UEFI subimage exceeds original partition"
        );
        rebuilt
            [self.compressed_subimage_offset..self.compressed_subimage_offset + compressed.len()]
            .copy_from_slice(&compressed);

        let old_section_padding =
            align(0, self.compressed_subimage_size, 4) - self.compressed_subimage_size;
        let new_section_padding = align(0, compressed.len(), 4) - compressed.len();
        let old_file_size = le_u24(&self.binary, self.file_header_offset + 0x14)? as usize;
        let new_file_size = if self.compressed_subimage_offset
            + self.compressed_subimage_size
            + old_section_padding
            >= self.file_header_offset + old_file_size
        {
            self.compressed_subimage_offset - self.file_header_offset + compressed.len()
        } else {
            old_file_size - self.compressed_subimage_size - old_section_padding
                + compressed.len()
                + new_section_padding
        };

        for index in 0..new_section_padding {
            rebuilt[self.compressed_subimage_offset + compressed.len() + index] = self.padding_byte;
        }

        let trailing_sections_len = self.file_header_offset + old_file_size
            - self.compressed_subimage_offset
            - self.compressed_subimage_size
            - old_section_padding;
        if trailing_sections_len > 0 {
            let old_start = self.compressed_subimage_offset
                + self.compressed_subimage_size
                + old_section_padding;
            let new_start =
                self.compressed_subimage_offset + compressed.len() + new_section_padding;
            rebuilt[new_start..new_start + trailing_sections_len]
                .copy_from_slice(&self.binary[old_start..old_start + trailing_sections_len]);
        }

        let old_file_padding = align(0, old_file_size, 8) - old_file_size;
        let new_file_padding = align(0, new_file_size, 8) - new_file_size;
        for index in 0..new_file_padding {
            rebuilt[self.file_header_offset + new_file_size + index] = self.padding_byte;
        }

        let old_tail_start = self.file_header_offset + old_file_size + old_file_padding;
        let new_tail_start = self.file_header_offset + new_file_size + new_file_padding;
        let volume_end = self.volume_header_offset + self.volume_size;
        ensure!(volume_end <= rebuilt.len(), "UEFI volume exceeds partition");
        if compressed.len() > self.compressed_subimage_size {
            let tail_len = volume_end - new_tail_start;
            rebuilt[new_tail_start..new_tail_start + tail_len]
                .copy_from_slice(&self.binary[old_tail_start..old_tail_start + tail_len]);
        } else {
            let tail_len = volume_end - old_tail_start;
            rebuilt[new_tail_start..new_tail_start + tail_len]
                .copy_from_slice(&self.binary[old_tail_start..old_tail_start + tail_len]);
            for byte in rebuilt[new_tail_start + tail_len..volume_end].iter_mut() {
                *byte = self.padding_byte;
            }
        }

        write_le_u24(
            &mut rebuilt,
            self.section_header_offset,
            compressed.len() as u32
                + le_u16(&self.binary, self.section_header_offset + 0x14)? as u32,
        )?;
        write_le_u24(
            &mut rebuilt,
            self.file_header_offset + 0x14,
            new_file_size as u32,
        )?;
        calculate_file_checksum(&mut rebuilt, self.file_header_offset)?;
        calculate_volume_checksum(&mut rebuilt, self.volume_header_offset)?;

        self.binary = rebuilt;
        Ok(self.binary)
    }

    fn file(&self, name: &str) -> Result<&EfiFile> {
        self.files
            .iter()
            .find(|file| file.name.eq_ignore_ascii_case(name))
            .with_context(|| format!("UEFI file {name} not found"))
    }

    fn clear_pe_checksum(&mut self, file: &EfiFile) -> Result<()> {
        let pe_offset = le_u32(&self.decompressed, file.binary_offset + 0x3c)? as usize;
        let checksum_offset = file
            .binary_offset
            .checked_add(pe_offset)
            .and_then(|offset| offset.checked_add(0x58))
            .context("PE checksum offset overflow")?;
        ensure!(
            checksum_offset + 4 <= self.decompressed.len(),
            "PE checksum offset is outside UEFI file"
        );
        write_le_u32(&mut self.decompressed, checksum_offset, 0)
    }
}

fn verify_volume_checksum(image: &[u8], offset: usize) -> Result<bool> {
    let size = le_u16(image, offset + 0x30)? as usize;
    let mut header = image
        .get(offset..offset + size)
        .context("UEFI volume header truncated")?
        .to_vec();
    write_le_u16(&mut header, 0x32, 0)?;
    Ok(le_u16(image, offset + 0x32)? == checksum16_le(&header))
}

fn calculate_volume_checksum(image: &mut [u8], offset: usize) -> Result<()> {
    let size = le_u16(image, offset + 0x30)? as usize;
    write_le_u16(image, offset + 0x32, 0)?;
    let checksum = checksum16_le(
        image
            .get(offset..offset + size)
            .context("UEFI volume header truncated")?,
    );
    write_le_u16(image, offset + 0x32, checksum)
}

fn verify_file_checksum(image: &[u8], offset: usize) -> Result<bool> {
    const FILE_HEADER_SIZE: usize = 0x18;
    let file_size = le_u24(image, offset + 0x14)? as usize;
    ensure!(offset + file_size <= image.len(), "UEFI file truncated");

    let mut header = image[offset..offset + FILE_HEADER_SIZE - 1].to_vec();
    write_le_u16(&mut header, 0x10, 0)?;
    if image[offset + 0x10] != checksum8(&header) {
        return Ok(false);
    }

    let file_checksum = image[offset + 0x11];
    if image[offset + 0x13] & 0x40 != 0 {
        Ok(file_checksum == checksum8(&image[offset + FILE_HEADER_SIZE..offset + file_size]))
    } else {
        Ok(file_checksum == 0xaa || file_checksum == 0x55)
    }
}

fn calculate_file_checksum(image: &mut [u8], offset: usize) -> Result<()> {
    const FILE_HEADER_SIZE: usize = 0x18;
    let file_size = le_u24(image, offset + 0x14)? as usize;
    write_le_u16(image, offset + 0x10, 0)?;
    let header_checksum = checksum8(&image[offset..offset + FILE_HEADER_SIZE - 1]);
    image[offset + 0x10] = header_checksum;

    if image[offset + 0x13] & 0x40 != 0 {
        image[offset + 0x11] = checksum8(&image[offset + FILE_HEADER_SIZE..offset + file_size]);
    } else {
        image[offset + 0x11] = 0xaa;
    }
    Ok(())
}

fn compress_lzma_alone(bytes: &[u8]) -> Result<Vec<u8>> {
    let options = xz2::stream::LzmaOptions::new_preset(9)
        .map_err(|err| anyhow!("failed to create LZMA encoder options: {err:?}"))?;
    let stream = xz2::stream::Stream::new_lzma_encoder(&options)
        .map_err(|err| anyhow!("failed to create LZMA encoder: {err:?}"))?;
    let mut encoder = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
    encoder
        .write_all(bytes)
        .context("failed to write data into LZMA encoder")?;
    let mut compressed = encoder.finish().context("failed to finish LZMA encoder")?;
    ensure!(
        compressed.len() >= 0x0d,
        "LZMA encoder produced a short stream"
    );
    compressed[5..0x0d].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    Ok(compressed)
}

fn ensure_fits(gpt: &ParsedGpt, name: &str, byte_len: usize) -> Result<()> {
    let partition = partition(gpt, name)?;
    let capacity = partition
        .sector_count()
        .checked_mul(SECTOR_SIZE)
        .context("partition capacity overflow")?;
    ensure!(
        byte_len as u64 <= capacity,
        "{name} artifact is too large: {} bytes > {} bytes",
        byte_len,
        capacity
    );
    Ok(())
}

fn partition<'a>(gpt: &'a ParsedGpt, name: &str) -> Result<&'a GptPartition> {
    gpt.partition(name)
        .with_context(|| format!("patched GPT does not contain {name}"))
}

fn validate_write_plan(entries: &[WritePlanEntry]) -> Result<()> {
    for entry in entries {
        ensure!(entry.byte_len != 0, "{} write length is zero", entry.name);
        let byte_start = entry
            .start_sector
            .checked_mul(SECTOR_SIZE)
            .context("write-plan byte offset overflow")?;
        let byte_end = byte_start
            .checked_add(entry.byte_len)
            .context("write-plan byte end overflow")?;
        ensure!(byte_end > byte_start, "{} write range is empty", entry.name);
    }

    Ok(())
}

pub(crate) fn print_write_plan(entries: &[WritePlanEntry]) {
    println!("write plan:");
    for entry in entries {
        println!(
            "  {:<9} start_sector={} bytes={} op={} source={}",
            entry.name, entry.start_sector, entry.byte_len, entry.operation, entry.source
        );
    }
}

pub(crate) fn render_write_plan(entries: &[WritePlanEntry]) -> String {
    let mut result = String::new();
    for entry in entries {
        result.push_str(&format!(
            "{} start_sector={} bytes={} op={} source={}\n",
            entry.name, entry.start_sector, entry.byte_len, entry.operation, entry.source
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{env, path::PathBuf};

    use anyhow::Result;

    use super::*;

    #[test]
    fn smoke_build_artifacts_from_env() -> Result<()> {
        let Some(ffu_path) = env::var_os("LP_EXTERNALS_TEST_FFU").map(PathBuf::from) else {
            return Ok(());
        };
        let Some(sbl3_path) = env::var_os("LP_EXTERNALS_TEST_SBL3").map(PathBuf::from) else {
            return Ok(());
        };

        let ffu = FfuMetadata::open(&ffu_path)?;
        let artifacts = build_jailbreak_artifacts(&ffu_path, &ffu, &sbl3_path)?;
        assert!(!artifacts.write_plan.is_empty());
        Ok(())
    }
}
