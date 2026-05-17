use anyhow::{Context, Result, ensure};

use crate::util::{decode_utf16_name, find_bytes, format_guid, le_u32, le_u64};

pub(crate) struct ParsedGpt {
    partitions: Vec<GptPartition>,
}

impl ParsedGpt {
    pub(crate) fn parse(gpt: &[u8]) -> Result<Self> {
        let layout = GptLayout::parse(gpt)?;
        let mut partitions = Vec::new();

        for index in 0..layout.partition_entry_count {
            let offset = layout
                .entries_offset
                .checked_add(
                    usize::try_from(index)
                        .context("partition index does not fit in usize")?
                        .checked_mul(layout.entry_size)
                        .context("partition entry offset overflow")?,
                )
                .context("partition entry offset overflow")?;
            let Some(entry) = gpt.get(offset..offset + layout.entry_size) else {
                break;
            };

            if entry[..16].iter().all(|byte| *byte == 0) {
                continue;
            }

            partitions.push(GptPartition {
                index: index + 1,
                type_guid: format_guid(&entry[0..16]),
                unique_guid: format_guid(&entry[16..32]),
                first_lba: le_u64(entry, 32)?,
                last_lba: le_u64(entry, 40)?,
                attrs: le_u64(entry, 48)?,
                name: decode_utf16_name(&entry[56..128]),
            });
        }

        Ok(Self { partitions })
    }

    pub(crate) fn partition(&self, name: &str) -> Option<&GptPartition> {
        self.partitions
            .iter()
            .find(|partition| partition.name.eq_ignore_ascii_case(name))
    }
}

struct GptLayout {
    header_offset: usize,
    header_size: u32,
    revision: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: String,
    partition_entries_lba: u64,
    partition_entry_count: u32,
    entry_size: usize,
    entries_offset: usize,
}

impl GptLayout {
    pub(crate) fn parse(gpt: &[u8]) -> Result<Self> {
        ensure!(
            gpt.len() >= 0x200,
            "GPT payload too short: {} bytes",
            gpt.len()
        );

        let header_offset = find_bytes(gpt, b"EFI PART").context("missing GPT header signature")?;
        let header = gpt
            .get(header_offset..)
            .context("GPT payload missing primary header")?;

        ensure!(header.len() >= 92, "GPT header too short");

        let revision = le_u32(header, 8)?;
        let header_size = le_u32(header, 12)?;
        let current_lba = le_u64(header, 24)?;
        let backup_lba = le_u64(header, 32)?;
        let first_usable_lba = le_u64(header, 40)?;
        let last_usable_lba = le_u64(header, 48)?;
        let disk_guid = format_guid(&header[56..72]);
        let partition_entries_lba = le_u64(header, 72)?;
        let partition_entry_count = le_u32(header, 80)?;
        let partition_entry_size = le_u32(header, 84)?;
        let entry_size = usize::try_from(partition_entry_size)
            .context("partition entry size does not fit in usize")?;
        ensure!(
            entry_size >= 128,
            "unsupported GPT entry size: {entry_size}"
        );
        ensure!(
            partition_entries_lba >= current_lba,
            "partition entries precede GPT header"
        );

        let entries_offset = header_offset
            .checked_add(
                usize::try_from(partition_entries_lba - current_lba)
                    .context("partition entries relative LBA does not fit in usize")?
                    .checked_mul(512)
                    .context("partition entries offset overflow")?,
            )
            .context("partition entries offset overflow")?;

        Ok(Self {
            header_offset,
            header_size,
            revision,
            current_lba,
            backup_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            partition_entries_lba,
            partition_entry_count,
            entry_size,
            entries_offset,
        })
    }
}

pub(crate) struct GptPartition {
    pub(crate) index: u32,
    pub(crate) type_guid: String,
    pub(crate) unique_guid: String,
    pub(crate) first_lba: u64,
    pub(crate) last_lba: u64,
    pub(crate) attrs: u64,
    pub(crate) name: String,
}

pub(crate) fn print_gpt(gpt: &[u8]) -> Result<()> {
    let layout = GptLayout::parse(gpt)?;
    let parsed = ParsedGpt::parse(gpt)?;

    println!("GPT header");
    println!("  header offset: {}", layout.header_offset);
    println!("  revision: 0x{:08x}", layout.revision);
    println!("  header size: {}", layout.header_size);
    println!("  current lba: {}", layout.current_lba);
    println!("  backup lba: {}", layout.backup_lba);
    println!("  first usable lba: {}", layout.first_usable_lba);
    println!("  last usable lba: {}", layout.last_usable_lba);
    println!("  disk guid: {}", layout.disk_guid);
    println!("  partition entries lba: {}", layout.partition_entries_lba);
    println!("  partition entry count: {}", layout.partition_entry_count);
    println!("  partition entry size: {}", layout.entry_size);

    println!();
    println!("Partitions");

    for partition in &parsed.partitions {
        let sectors = partition
            .last_lba
            .saturating_sub(partition.first_lba)
            .saturating_add(1);

        println!(
            "  {:>3}: {:<36} first={} last={} sectors={} attrs=0x{:016x}",
            partition.index,
            partition.name,
            partition.first_lba,
            partition.last_lba,
            sectors,
            partition.attrs
        );
        println!("       type:   {}", partition.type_guid);
        println!("       unique: {}", partition.unique_guid);
    }

    if parsed.partitions.is_empty() {
        println!("  no populated partition entries found");
    }

    Ok(())
}
