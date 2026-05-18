use anyhow::{Context, Result, bail, ensure};

use crate::util::{
    decode_utf16_name, find_bytes, format_guid, le_u32, le_u64, write_le_u32, write_le_u64,
};

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

impl GptPartition {
    pub(crate) fn sector_count(&self) -> u64 {
        self.last_lba
            .saturating_sub(self.first_lba)
            .saturating_add(1)
    }
}

pub(crate) fn insert_spec_a_hack(gpt: &[u8]) -> Result<Vec<u8>> {
    let layout = GptLayout::parse(gpt)?;
    let mut patched = gpt.to_vec();

    if find_partition_entry_offset(&layout, &patched, "HACK")?.is_some() {
        bail!("GPT already contains a HACK partition; refusing to apply Spec A hack twice");
    }

    let sbl1_offset = find_partition_entry_offset(&layout, &patched, "SBL1")?
        .context("GPT does not contain SBL1")?;
    let sbl2_offset = find_partition_entry_offset(&layout, &patched, "SBL2")?
        .context("GPT does not contain SBL2")?;
    let hack_offset = find_empty_entry_offset(&layout, &patched)?
        .context("GPT has no empty partition entry for HACK")?;

    let sbl1_first = le_u64(&patched, sbl1_offset + 32)?;
    let sbl1_last = le_u64(&patched, sbl1_offset + 40)?;
    ensure!(
        sbl1_last > sbl1_first,
        "SBL1 is too small to donate a HACK sector"
    );

    let mut hack_entry = vec![0; layout.entry_size];
    hack_entry[0..16].copy_from_slice(&patched[sbl2_offset..sbl2_offset + 16]);
    hack_entry[16..32].copy_from_slice(&patched[sbl2_offset + 16..sbl2_offset + 32]);
    write_le_u64(&mut hack_entry, 32, sbl1_last)?;
    write_le_u64(&mut hack_entry, 40, sbl1_last)?;
    hack_entry[48..56].copy_from_slice(&patched[sbl2_offset + 48..sbl2_offset + 56]);
    write_utf16_name(&mut hack_entry[56..128], "HACK");

    write_le_u64(&mut patched, sbl1_offset + 40, sbl1_last - 1)?;
    patched[sbl2_offset..sbl2_offset + 32].fill(0x74);
    patched[hack_offset..hack_offset + layout.entry_size].copy_from_slice(&hack_entry);

    rebuild_primary_gpt_crc(&layout, &mut patched)?;
    Ok(patched)
}

fn find_partition_entry_offset(
    layout: &GptLayout,
    gpt: &[u8],
    name: &str,
) -> Result<Option<usize>> {
    for index in 0..layout.partition_entry_count {
        let offset = partition_entry_offset(layout, index)?;
        let Some(entry) = gpt.get(offset..offset + layout.entry_size) else {
            break;
        };
        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }
        let entry_name = decode_utf16_name(&entry[56..128]);
        if entry_name.eq_ignore_ascii_case(name) {
            return Ok(Some(offset));
        }
    }

    Ok(None)
}

fn find_empty_entry_offset(layout: &GptLayout, gpt: &[u8]) -> Result<Option<usize>> {
    for index in 0..layout.partition_entry_count {
        let offset = partition_entry_offset(layout, index)?;
        let Some(entry) = gpt.get(offset..offset + layout.entry_size) else {
            break;
        };
        if entry[..16].iter().all(|byte| *byte == 0) {
            return Ok(Some(offset));
        }
    }

    Ok(None)
}

fn partition_entry_offset(layout: &GptLayout, index: u32) -> Result<usize> {
    layout
        .entries_offset
        .checked_add(
            usize::try_from(index)
                .context("partition index does not fit in usize")?
                .checked_mul(layout.entry_size)
                .context("partition entry offset overflow")?,
        )
        .context("partition entry offset overflow")
}

fn write_utf16_name(target: &mut [u8], name: &str) {
    target.fill(0);
    for (index, word) in name.encode_utf16().take(target.len() / 2).enumerate() {
        target[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
}

fn rebuild_primary_gpt_crc(layout: &GptLayout, gpt: &mut [u8]) -> Result<()> {
    let table_size = usize::try_from(layout.partition_entry_count)
        .context("partition entry count does not fit in usize")?
        .checked_mul(layout.entry_size)
        .context("partition table size overflow")?;
    let table_end = layout
        .entries_offset
        .checked_add(table_size)
        .context("partition table end overflow")?;
    ensure!(table_end <= gpt.len(), "partition table exceeds GPT buffer");

    let table_crc = crc32fast::hash(&gpt[layout.entries_offset..table_end]);
    write_le_u32(gpt, layout.header_offset + 0x58, table_crc)?;
    write_le_u32(gpt, layout.header_offset + 0x10, 0)?;

    let header_size = usize::try_from(layout.header_size).context("GPT header size overflow")?;
    let header_end = layout
        .header_offset
        .checked_add(header_size)
        .context("GPT header end overflow")?;
    ensure!(header_end <= gpt.len(), "GPT header exceeds buffer");
    let header_crc = crc32fast::hash(&gpt[layout.header_offset..header_end]);
    write_le_u32(gpt, layout.header_offset + 0x10, header_crc)?;

    Ok(())
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
