use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};

use crate::{ffu::FfuMetadata, gpt::print_gpt};

pub(crate) fn info(path: &Path) -> Result<()> {
    let ffu = FfuMetadata::open(path)?;

    println!("path: {}", path.display());
    println!("file size: {}", ffu.file_size);
    println!("chunk size: {}", ffu.chunk_size);
    println!("platform ID: {}", ffu.platform_id);
    println!("security header: {} bytes", ffu.security_header_len);
    println!("image header: {} bytes", ffu.image_header_len);
    println!("store header: {} bytes", ffu.store_header_len);
    println!("header size: {}", ffu.header_size);
    println!("payload size: {}", ffu.payload_size);
    println!("total chunks: {}", ffu.total_chunk_count);
    println!("mapped disk chunks: {}", ffu.chunk_indexes.len());

    Ok(())
}

pub(crate) fn partitions(path: &Path) -> Result<()> {
    let ffu = FfuMetadata::open(path)?;
    let gpt = ffu.get_sectors(path, 1, 0x21)?;
    print_gpt(&gpt)
}

pub(crate) fn extract(path: &Path, partition: &str, output: &Path) -> Result<()> {
    let ffu = FfuMetadata::open(path)?;
    let bytes = ffu.get_partition(path, partition)?;

    write_output(output, &bytes)?;
    println!(
        "extracted {} ({} bytes) to {}",
        partition,
        bytes.len(),
        output.display()
    );

    Ok(())
}

pub(crate) fn extract_sectors(
    path: &Path,
    start_sector: u32,
    sector_count: u32,
    output: &Path,
) -> Result<()> {
    ensure!(sector_count != 0, "sector count must not be zero");
    let ffu = FfuMetadata::open(path)?;
    let bytes = ffu.get_sectors(path, start_sector as usize, sector_count as usize)?;
    let end_sector = start_sector
        .checked_add(sector_count - 1)
        .context("sector range overflows")?;

    write_output(output, &bytes)?;
    println!(
        "extracted sectors {}..{} ({} bytes) to {}",
        start_sector,
        end_sector,
        bytes.len(),
        output.display()
    );

    Ok(())
}

fn write_output(output: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    fs::write(output, &bytes).with_context(|| format!("failed to write {}", output.display()))?;
    Ok(())
}
