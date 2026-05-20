use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::{
    flash::{FlashAppInfo, flash_raw_sectors, read_flash_app_info, read_flash_param},
    gpt::ParsedGpt,
    uefi::{Endpoints, LumiaApp, identify_app, require_app, send_raw_command, with_device},
    util::{ascii_dump, hex_dump_compact},
};

const SECTOR_SIZE: usize = 0x200;
const RAW_FLASH_HEADER_SIZE: usize = 0x40;
const DEFAULT_RAW_FLASH_CHUNK_SIZE: usize = 0x200000;

pub(crate) fn raw_write_partition(
    vid: u16,
    pid: u16,
    wait: bool,
    partition_name: &str,
    image_path: &Path,
    confirm_raw_write: bool,
    dry_run: bool,
) -> Result<()> {
    ensure!(
        !partition_name.is_empty(),
        "partition name must not be empty"
    );
    if !dry_run {
        ensure!(
            confirm_raw_write,
            "raw-write-partition is destructive; pass --confirm-raw-write or use --dry-run"
        );
    }

    let image =
        fs::read(image_path).with_context(|| format!("failed to read {}", image_path.display()))?;
    ensure!(!image.is_empty(), "{} is empty", image_path.display());
    ensure!(
        image.len().is_multiple_of(SECTOR_SIZE),
        "{} is not sector-aligned",
        image_path.display()
    );
    let image_sha256 = sha256_hex(&image);

    with_device(vid, pid, wait, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::FlashApp, "flash raw-write-partition")?;

        let flash_info = read_flash_app_info(handle, endpoints)?;
        let security_status = read_flash_param(handle, endpoints, "SS")?;
        validate_raw_write_security_status(&security_status)?;

        let live_gpt = read_live_gpt(handle, endpoints)?;
        let partitions = ParsedGpt::parse(&live_gpt).context("failed to parse live GPT")?;
        let partition = partitions
            .partition(partition_name)
            .with_context(|| format!("live GPT does not contain partition {partition_name}"))?;
        let partition_bytes = partition
            .sector_count()
            .checked_mul(SECTOR_SIZE as u64)
            .context("partition byte size overflow")?;
        ensure!(
            image.len() as u64 == partition_bytes,
            "image size {} does not match partition {partition_name} size {partition_bytes}",
            image.len()
        );
        let first_sector = u32::try_from(partition.first_lba)
            .context("partition start sector does not fit FlashApp NOKF")?;
        let chunk_size = raw_flash_chunk_size(&flash_info)?;

        println!("FlashApp raw partition write:");
        println!("  partition: {}", partition.name);
        println!("  index: {}", partition.index);
        println!(
            "  sectors: {}..={} ({} sectors)",
            partition.first_lba,
            partition.last_lba,
            partition.sector_count()
        );
        println!("  bytes: {}", image.len());
        println!("  image: {}", image_path.display());
        println!("  sha256: {image_sha256}");
        println!("  chunk size: {chunk_size} bytes");

        if dry_run {
            println!("dry run: no raw flash writes sent");
            return Ok(());
        }

        write_partition_image(handle, endpoints, first_sector, &image, chunk_size)?;
        println!("FlashApp raw partition write: complete");
        Ok(())
    })
}

fn validate_raw_write_security_status(value: &[u8]) -> Result<()> {
    ensure!(
        value.len() >= 8,
        "FlashApp SS parameter is too short: {} bytes",
        value.len()
    );

    let platform_secure_boot = value[1] != 0;
    let secure_ffu = value[2] != 0;
    let uefi_secure_boot = value[6] != 0;

    println!("platform secure boot: {platform_secure_boot}");
    println!("secure FFU efuse: {secure_ffu}");
    println!("UEFI secure boot: {uefi_secure_boot}");

    ensure!(!secure_ffu, "raw partition writes require secure_ffu=false");
    Ok(())
}

fn raw_flash_chunk_size(info: &FlashAppInfo) -> Result<usize> {
    let mut chunk_size = info
        .write_buffer_size
        .map(|size| size as usize)
        .unwrap_or(DEFAULT_RAW_FLASH_CHUNK_SIZE);

    if let Some(transfer_size) = info.transfer_size {
        let transfer_payload_limit = (transfer_size as usize)
            .checked_sub(RAW_FLASH_HEADER_SIZE)
            .context("FlashApp transfer size is smaller than a raw flash header")?;
        chunk_size = chunk_size.min(transfer_payload_limit);
    }

    chunk_size -= chunk_size % SECTOR_SIZE;
    ensure!(chunk_size != 0, "FlashApp raw flash chunk size is zero");
    Ok(chunk_size)
}

fn write_partition_image(
    handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    endpoints: &Endpoints,
    first_sector: u32,
    image: &[u8],
    chunk_size: usize,
) -> Result<()> {
    ensure!(
        chunk_size.is_multiple_of(SECTOR_SIZE),
        "raw flash chunk size is not sector-aligned"
    );
    let total_chunks = image.len().div_ceil(chunk_size);

    for (index, chunk) in image.chunks(chunk_size).enumerate() {
        ensure!(
            chunk.len().is_multiple_of(SECTOR_SIZE),
            "raw flash chunk {} is not sector-aligned",
            index + 1
        );
        let sector_offset = u32::try_from(index * (chunk_size / SECTOR_SIZE))
            .context("raw flash sector offset overflow")?;
        let chunk_start_sector = first_sector
            .checked_add(sector_offset)
            .context("raw flash start sector overflow")?;
        let progress = chunk_progress(index, total_chunks);

        println!(
            "  chunk {}/{} start={} bytes={}",
            index + 1,
            total_chunks,
            chunk_start_sector,
            chunk.len()
        );
        flash_raw_sectors(handle, endpoints, chunk_start_sector, chunk, progress)
            .with_context(|| format!("failed to write raw flash chunk {}", index + 1))?;
    }

    Ok(())
}

fn chunk_progress(index: usize, total_chunks: usize) -> u8 {
    if total_chunks <= 1 {
        return 100;
    }
    (index * 100 / (total_chunks - 1)).min(100) as u8
}

fn read_live_gpt(
    handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    endpoints: &Endpoints,
) -> Result<Vec<u8>> {
    let response = send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKT")?;
    ensure!(
        response.len() >= 8,
        "NOKT response too short: {} bytes",
        response.len()
    );
    if &response[..4] == b"NOKU" {
        bail!("device reported NOKT as unsupported");
    }
    ensure!(
        &response[..4] == b"NOKT",
        "unexpected NOKT response signature: {}",
        ascii_dump(&response[..response.len().min(4)])
    );
    let error = u16::from_be_bytes([response[6], response[7]]);
    ensure!(error == 0, "NOKT failed with error 0x{error:04x}");
    let gpt = response[8..].to_vec();
    ensure!(
        gpt.len().is_multiple_of(SECTOR_SIZE),
        "NOKT GPT payload is not sector-aligned: {} bytes",
        gpt.len()
    );
    Ok(gpt)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_dump_compact(&Sha256::digest(bytes))
}
