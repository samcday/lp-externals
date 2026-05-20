use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};

use crate::{
    edl::{self, EdlMode},
    qcom::{QcomCandidate, QualcommImage, contains_utf16le, read_qcom_candidates},
    util::hex_dump_compact,
};

pub(crate) fn probe(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let info = edl::probe(vid, pid, wait)?;

    println!("usb: {:04x}:{:04x}", vid, pid);
    println!("location: bus {} device {}", info.bus, info.address);
    println!(
        "manufacturer: {}",
        info.manufacturer.as_deref().unwrap_or("unknown")
    );
    println!("product: {}", info.product.as_deref().unwrap_or("unknown"));
    println!("mode: {}", info.mode.name());
    println!("interface: {}", info.endpoints.interface);
    println!("bulk in: 0x{:02x}", info.endpoints.in_addr);
    println!("bulk out: 0x{:02x}", info.endpoints.out_addr);

    Ok(())
}

pub(crate) fn dload_ping(vid: u16, pid: u16, wait: bool) -> Result<()> {
    edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::dload_ping(handle, endpoints)
    })?;
    println!("DLOAD ping: ok");

    Ok(())
}

pub(crate) fn dload_rkh(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let rkh = edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::dload_read_rkh(handle, endpoints)
    })?;
    println!("DLOAD RKH: {}", hex_dump_compact(&rkh));

    Ok(())
}

pub(crate) fn dload_load(
    vid: u16,
    pid: u16,
    wait: bool,
    loader_path: &Path,
    address: u32,
) -> Result<()> {
    let rkh = edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::dload_read_rkh(handle, endpoints)
    })?;
    println!("DLOAD RKH: {}", hex_dump_compact(&rkh));

    let loaders = matching_loader_candidates(loader_path, &rkh)?;
    ensure!(
        !loaders.is_empty(),
        "no matching QHSUSB_ARMPRG loaders found in {}",
        loader_path.display()
    );
    println!("matching loaders: {}", loaders.len());

    let mut last_error = None;
    for (index, loader) in loaders.into_iter().enumerate() {
        println!(
            "attempt {}: {} format={} size={} address=0x{address:08x}",
            index + 1,
            loader.name,
            loader.format,
            loader.bytes.len()
        );

        let result =
            edl::with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
                edl::dload_send_to_memory(handle, endpoints, address, &loader.bytes)?;
                edl::dload_start_bootloader(handle, endpoints, address)
            });

        match result {
            Ok(()) => {
                println!("loader started");
                println!("run `lp-externals edl probe` to confirm QHSUSB_ARMPRG mode");
                return Ok(());
            }
            Err(err) => {
                if let Ok(info) = edl::probe(vid, pid, false) {
                    if info.mode == EdlMode::Armprg {
                        println!("device reports QHSUSB_ARMPRG after loader start");
                        return Ok(());
                    }
                }
                println!("attempt failed: {err:#}");
                last_error = Some(err);
            }
        }
    }

    if let Some(err) = last_error {
        Err(err).context("all matching loader attempts failed")
    } else {
        bail!("no loader attempts were made")
    }
}

pub(crate) fn dload_reboot(vid: u16, pid: u16, wait: bool) -> Result<()> {
    edl::with_device_allow_release_disconnect(vid, pid, wait, |handle, endpoints| {
        edl::dload_reboot(handle, endpoints)
    })?;
    println!("DLOAD reboot: sent");

    Ok(())
}

fn matching_loader_candidates(path: &Path, rrkh: &[u8]) -> Result<Vec<QcomCandidate>> {
    ensure!(
        rrkh.len() == 0x20,
        "RKH must be 32 bytes, got {}",
        rrkh.len()
    );
    let candidates = read_qcom_candidates(path)?;
    let rkh_is_blank = rrkh.iter().all(|byte| *byte == 0);
    let mut matches = Vec::new();

    for candidate in candidates {
        if candidate.bytes.len() > 0x80000 {
            continue;
        }
        if !contains_utf16le(&candidate.bytes, "QHSUSB_ARMPRG") {
            continue;
        }
        if !rkh_is_blank {
            let image = match QualcommImage::parse(&candidate.bytes, 0) {
                Ok(image) => image,
                Err(_) => continue,
            };
            if image.root_key_hash.as_deref() != Some(rrkh) {
                continue;
            }
        }
        matches.push(candidate);
    }

    Ok(matches)
}

pub(crate) fn armprg_hello(vid: u16, pid: u16, wait: bool) -> Result<()> {
    edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::armprg_hello(handle, endpoints)
    })?;
    println!("ARMPRG hello: ok");

    Ok(())
}

pub(crate) fn armprg_open(vid: u16, pid: u16, wait: bool, partition: u16) -> Result<()> {
    ensure!(
        partition <= u8::MAX as u16,
        "ARMPRG partition ID must fit in one byte"
    );
    edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::armprg_hello(handle, endpoints)?;
        edl::armprg_set_security_mode(handle, endpoints, 0)?;
        edl::armprg_open_partition(handle, endpoints, partition as u8)
    })?;
    println!("ARMPRG partition 0x{partition:02x}: open");

    Ok(())
}

pub(crate) fn armprg_close(vid: u16, pid: u16, wait: bool) -> Result<()> {
    edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::armprg_close_partition(handle, endpoints)
    })?;
    println!("ARMPRG partition: closed");

    Ok(())
}

pub(crate) fn armprg_write(
    vid: u16,
    pid: u16,
    wait: bool,
    partition: u16,
    start_sector: u32,
    file: &Path,
    confirm_raw_write: bool,
) -> Result<()> {
    ensure!(
        confirm_raw_write,
        "pass --confirm-raw-write to write raw flash"
    );
    ensure!(
        partition <= u8::MAX as u16,
        "ARMPRG partition ID must fit in one byte"
    );
    let start_byte = start_sector
        .checked_mul(0x200)
        .context("start sector byte offset overflow")?;
    let bytes = fs::read(file).with_context(|| format!("failed to read {}", file.display()))?;
    ensure!(!bytes.is_empty(), "{} is empty", file.display());
    let byte_end = start_byte
        .checked_add(u32::try_from(bytes.len()).context("file is too large for ARMPRG u32 offset")?)
        .context("raw write byte range overflow")?;

    println!("ARMPRG raw write:");
    println!("  file: {}", file.display());
    println!("  partition: 0x{partition:02x}");
    println!("  start sector: {start_sector}");
    println!("  byte range: 0x{start_byte:08x}..0x{byte_end:08x}");
    println!("  bytes: {}", bytes.len());
    println!("  sha256: {}", sha256_hex(&bytes));

    edl::with_device(vid, pid, wait, |handle, endpoints| {
        edl::armprg_hello(handle, endpoints)?;
        edl::armprg_set_security_mode(handle, endpoints, 0)?;
        edl::armprg_open_partition(handle, endpoints, partition as u8)?;
        let flash_result = edl::armprg_flash(handle, endpoints, start_byte, &bytes);
        let close_result = edl::armprg_close_partition(handle, endpoints);
        flash_result.and(close_result)
    })?;
    println!("ARMPRG raw write: complete");

    Ok(())
}

pub(crate) fn armprg_reboot(vid: u16, pid: u16, wait: bool) -> Result<()> {
    edl::with_device_allow_release_disconnect(vid, pid, wait, |handle, endpoints| {
        edl::armprg_reboot(handle, endpoints)
    })?;
    println!("ARMPRG reboot: sent");

    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex_dump_compact(&Sha256::digest(bytes))
}
