use std::path::Path;

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
