use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};

use crate::{
    gpt::ParsedGpt,
    util::{ascii_lossy, le_u32},
};

pub(crate) struct ParsedFfu {
    pub(crate) bytes: Vec<u8>,
    pub(crate) file_size: u64,
    pub(crate) chunk_size: usize,
    pub(crate) platform_id: String,
    pub(crate) security_header_len: usize,
    pub(crate) image_header_len: usize,
    pub(crate) store_header_len: usize,
    pub(crate) header_size: usize,
    pub(crate) payload_size: u64,
    pub(crate) total_chunk_count: u64,
    pub(crate) chunk_indexes: Vec<Option<usize>>,
}

impl ParsedFfu {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let file_size = u64::try_from(bytes.len()).context("FFU too large")?;

        ensure!(bytes.len() >= 0x20, "FFU too short");
        ensure!(
            bytes.get(0x04..0x10) == Some(b"SignedImage "),
            "missing SignedImage header"
        );

        let chunk_size = le_u32(&bytes, 0x10)? as usize * 1024;
        ensure!(chunk_size != 0, "invalid zero chunk size");
        let security_header_size = le_u32(&bytes, 0x00)? as usize;
        let catalog_size = le_u32(&bytes, 0x18)? as usize;
        let hash_table_size = le_u32(&bytes, 0x1c)? as usize;
        let security_header_len = round_up_to_chunk(
            security_header_size + catalog_size + hash_table_size,
            chunk_size,
        );

        ensure!(
            bytes.len() >= security_header_len + 0x1c,
            "FFU too short for image header"
        );
        ensure!(
            bytes.get(security_header_len + 0x04..security_header_len + 0x10)
                == Some(b"ImageFlash  "),
            "missing ImageFlash header"
        );
        let image_header_size = le_u32(&bytes, security_header_len)? as usize;
        let manifest_size = le_u32(&bytes, security_header_len + 0x10)? as usize;
        let image_header_len = round_up_to_chunk(image_header_size + manifest_size, chunk_size);

        let store_offset = security_header_len + image_header_len;
        ensure!(
            bytes.len() >= store_offset + 248,
            "FFU too short for store header"
        );
        let platform_id = ascii_lossy(&bytes[store_offset + 0x0c..store_offset + 0x0c + 192])
            .trim_matches(['\0', ' '])
            .to_string();
        let write_descriptor_count = le_u32(&bytes, store_offset + 208)? as usize;
        let write_descriptor_len = le_u32(&bytes, store_offset + 212)? as usize;
        let validate_descriptor_len = le_u32(&bytes, store_offset + 220)? as usize;
        let store_header_len = round_up_to_chunk(
            248 + write_descriptor_len + validate_descriptor_len,
            chunk_size,
        );
        ensure!(
            bytes.len() >= store_offset + store_header_len,
            "FFU too short for full store header"
        );

        let store = &bytes[store_offset..store_offset + store_header_len];
        let mut highest_chunk_index = 0usize;
        let mut entry_offset = 248 + validate_descriptor_len;
        let mut total_chunk_count = 0usize;

        for _ in 0..write_descriptor_count {
            let location_count = le_u32(store, entry_offset)? as usize;
            let chunk_count = le_u32(store, entry_offset + 4)? as usize;

            for index in 0..location_count {
                let location_offset = entry_offset + 8 + index * 8;
                let disk_access_method = le_u32(store, location_offset)?;
                let chunk_index = le_u32(store, location_offset + 4)? as usize;

                if disk_access_method == 0 && chunk_count > 0 {
                    highest_chunk_index = highest_chunk_index.max(chunk_index + chunk_count - 1);
                }
            }

            entry_offset += 8 + location_count * 8;
            total_chunk_count += chunk_count;
        }

        let mut chunk_indexes = vec![None; highest_chunk_index + 1];
        entry_offset = 248 + validate_descriptor_len;
        let mut ffu_chunk_index = 0usize;

        for _ in 0..write_descriptor_count {
            let location_count = le_u32(store, entry_offset)? as usize;
            let chunk_count = le_u32(store, entry_offset + 4)? as usize;

            for index in 0..location_count {
                let location_offset = entry_offset + 8 + index * 8;
                let disk_access_method = le_u32(store, location_offset)?;
                let chunk_index = le_u32(store, location_offset + 4)? as usize;

                if disk_access_method == 0 {
                    for chunk_offset in 0..chunk_count {
                        chunk_indexes[chunk_index + chunk_offset] =
                            Some(ffu_chunk_index + chunk_offset);
                    }
                }
            }

            entry_offset += 8 + location_count * 8;
            ffu_chunk_index += chunk_count;
        }

        let header_size = security_header_len + image_header_len + store_header_len;
        let payload_size = (total_chunk_count as u64) * (chunk_size as u64);
        let expected_size = header_size as u64 + payload_size;
        ensure!(
            expected_size == file_size,
            "bad FFU size: expected {expected_size}, actual {file_size}"
        );

        Ok(Self {
            bytes,
            file_size,
            chunk_size,
            platform_id,
            security_header_len,
            image_header_len,
            store_header_len,
            header_size,
            payload_size,
            total_chunk_count: total_chunk_count as u64,
            chunk_indexes,
        })
    }

    pub(crate) fn get_sectors(&self, start_sector: usize, sector_count: usize) -> Result<Vec<u8>> {
        let start = start_sector * 0x200;
        let size = sector_count * 0x200;
        let mut result = vec![0; size];
        let sectors_per_chunk = self.chunk_size / 0x200;

        ensure!(sectors_per_chunk != 0, "invalid sectors per chunk");

        let first_chunk = start_sector / sectors_per_chunk;
        let last_sector = start_sector + sector_count - 1;
        let last_chunk = last_sector / sectors_per_chunk;

        for chunk_index in first_chunk..=last_chunk {
            let Some(Some(ffu_chunk_index)) = self.chunk_indexes.get(chunk_index) else {
                continue;
            };
            let source_offset = self.header_size + ffu_chunk_index * self.chunk_size;
            let target_chunk_start = chunk_index * self.chunk_size;
            let copy_start = start.max(target_chunk_start);
            let copy_end = (start + size).min(target_chunk_start + self.chunk_size);

            if copy_start >= copy_end {
                continue;
            }

            let source_start = source_offset + (copy_start - target_chunk_start);
            let source_end = source_start + (copy_end - copy_start);
            let target_start = copy_start - start;
            let target_end = target_start + (copy_end - copy_start);

            result[target_start..target_end].copy_from_slice(&self.bytes[source_start..source_end]);
        }

        Ok(result)
    }

    pub(crate) fn get_partition(&self, name: &str) -> Result<Vec<u8>> {
        let gpt_bytes = self.get_sectors(1, 0x21)?;
        let gpt = ParsedGpt::parse(&gpt_bytes)?;
        let partition = gpt
            .partition(name)
            .with_context(|| format!("FFU does not contain partition {name}"))?;
        let sector_count = partition
            .last_lba
            .checked_sub(partition.first_lba)
            .and_then(|sectors| sectors.checked_add(1))
            .context("partition sector range underflow")?;
        let start_sector = usize::try_from(partition.first_lba)
            .context("partition start sector does not fit in usize")?;
        let sector_count =
            usize::try_from(sector_count).context("partition size does not fit in usize")?;

        self.get_sectors(start_sector, sector_count)
    }
}

fn round_up_to_chunk(size: usize, chunk_size: usize) -> usize {
    size.div_ceil(chunk_size) * chunk_size
}
