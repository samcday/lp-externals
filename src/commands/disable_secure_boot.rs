use std::{fs, io::Read, path::Path};

use anyhow::{Context, Result, bail, ensure};
use flate2::read::GzDecoder;

use crate::{
    commands::reset,
    ffu::FfuMetadata,
    flash::{
        flash_raw_sectors, read_flash_app_info, read_flash_param, validate_ffu_against_flash_app,
    },
    gpt::{ParsedGpt, prepare_spec_a_secure_boot_nv},
    lumiadb::{
        cached_donor_ffu_path, cached_ffu_path, donor_ffu_url, download_file,
        fetch_lumiadb_database, make_exact_lumiadb_plan, print_lumiadb_plan,
    },
    qcom::extract_root_key_hash,
    secure_boot::{
        MobileStartupPatchStatus, build_spec_a_efiesp_payloads, patch_spec_a_efiesp,
        spec_a_mobilestartup_patch_status,
    },
    uefi::{
        LumiaApp, ascii_param_value, identify_app, make_phone_info_read_request,
        parse_phone_info_response, require_app, send_raw_command, switch_to_flash_app,
        switch_to_phone_info_app, with_device,
    },
    util::{ascii_dump, hex_dump_compact},
};

const SBA_COMPRESSED: &[u8] = include_bytes!("../../assets/wpinternals/SBA");
const SECTOR_SIZE: u64 = 0x200;
const RAW_FLASH_CHUNK_SIZE: usize = 0x200000;

pub(crate) fn run(
    vid: u16,
    pid: u16,
    wait: bool,
    confirm_imei: Option<&str>,
    dry_run: bool,
    no_reset: bool,
) -> Result<()> {
    if let Some(confirm_imei) = confirm_imei {
        ensure!(!confirm_imei.is_empty(), "--confirm-imei must not be empty");
        ensure!(confirm_imei.is_ascii(), "--confirm-imei must be ASCII");
    } else if !dry_run {
        bail!("disable-secure-boot is destructive; pass --confirm-imei <IMEI> or use --dry-run");
    }

    switch_to_phone_info_app(vid, pid, wait).context("failed to switch to PhoneInfoApp")?;
    let phone = read_phone_identity(vid, pid)?;
    println!("phone type: {}", phone.product_type);
    println!("product code: {}", phone.product_code);
    println!("imei: {}", mask_imei(&phone.imei));

    if let Some(confirm_imei) = confirm_imei {
        if phone.imei != confirm_imei {
            bail!(
                "IMEI confirmation mismatch: phone IMEI is {}, confirmation was {}. Secure-boot disable was not started.",
                mask_imei(&phone.imei),
                mask_imei(confirm_imei)
            );
        }
    }

    println!("fetching LumiaDB metadata");
    let database = fetch_lumiadb_database()?;
    let plan = make_exact_lumiadb_plan(&database, &phone.product_type, &phone.product_code)?;
    print_lumiadb_plan(&plan);

    let stock_ffu_path = cached_ffu_path(&plan)?;
    ensure_parent(&stock_ffu_path)?;
    let runtime = tokio::runtime::Runtime::new().context("failed to create download runtime")?;
    runtime.block_on(download_file(&plan.ffu_url, &stock_ffu_path))?;

    let stock_ffu = FfuMetadata::open(&stock_ffu_path)
        .with_context(|| format!("failed to parse FFU {}", stock_ffu_path.display()))?;
    println!("stock ffu: {}", stock_ffu_path.display());
    println!("stock ffu platform: {}", stock_ffu.platform_id);
    println!("stock ffu chunk size: {}", stock_ffu.chunk_size);

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    let (flash_info, phone_rrkh, flash_version, security_status, live_gpt) =
        with_device(vid, pid, false, |handle, endpoints| {
            let flash_info = read_flash_app_info(handle, endpoints)?;
            let phone_rrkh = read_flash_param(handle, endpoints, "RRKH")?;
            let flash_version = read_flash_param(handle, endpoints, "FAI")?;
            let security_status = read_flash_param(handle, endpoints, "SS")?;
            let live_gpt = read_live_gpt(handle, endpoints)?;
            Ok((
                flash_info,
                phone_rrkh,
                flash_version,
                security_status,
                live_gpt,
            ))
        })?;
    validate_preflight(
        &stock_ffu_path,
        &stock_ffu,
        &flash_info,
        &phone_rrkh,
        &flash_version,
        &security_status,
    )?;

    let live_partitions = ParsedGpt::parse(&live_gpt).context("failed to parse live GPT")?;
    let efiesp_partition = live_partitions
        .partition("EFIESP")
        .context("live GPT does not contain EFIESP")?;
    let efiesp_first_sector = u32::try_from(efiesp_partition.first_lba)
        .context("EFIESP start sector does not fit FlashApp NOKF")?;
    let efiesp_sector_count = efiesp_partition.sector_count();
    let nv_update = prepare_spec_a_secure_boot_nv(&live_gpt)
        .context("failed to prepare UEFI_BS_NV GPT split")?;
    let nv_first_sector = u32::try_from(nv_update.uefi_bs_nv.first_lba)
        .context("UEFI_BS_NV start sector does not fit FlashApp NOKF")?;

    let stock_efiesp = stock_ffu
        .get_partition(&stock_ffu_path, "EFIESP")
        .context("failed to extract stock EFIESP")?;
    let mut patched_efiesp = stock_efiesp.clone();
    let donor_efiesp = match spec_a_mobilestartup_patch_status(&patched_efiesp)? {
        MobileStartupPatchStatus::Supported { hash } => {
            println!("stock mobilestartup.efi is supported: {hash}");
            None
        }
        MobileStartupPatchStatus::AlreadyPatched { hash } => {
            println!("stock mobilestartup.efi is already patched: {hash}");
            None
        }
        MobileStartupPatchStatus::Unsupported { hash } => {
            println!("stock mobilestartup.efi is unsupported: {hash}");
            let donor_url = donor_ffu_url();
            let donor_ffu_path = cached_donor_ffu_path()?;
            ensure_parent(&donor_ffu_path)?;
            runtime.block_on(download_file(&donor_url, &donor_ffu_path))?;
            let donor_ffu = FfuMetadata::open(&donor_ffu_path).with_context(|| {
                format!("failed to parse donor FFU {}", donor_ffu_path.display())
            })?;
            println!("donor ffu: {}", donor_ffu_path.display());
            Some(
                donor_ffu
                    .get_partition(&donor_ffu_path, "EFIESP")
                    .context("failed to extract donor EFIESP")?,
            )
        }
    };

    let efiesp_patch = patch_spec_a_efiesp(&mut patched_efiesp, donor_efiesp.as_deref())?;
    println!(
        "mobilestartup source: {}",
        efiesp_patch.mobilestartup_source.label()
    );
    println!(
        "mobilestartup hash: {} -> {}",
        efiesp_patch.mobilestartup_hash_before, efiesp_patch.mobilestartup_hash_after
    );
    println!("BCD changed: {}", efiesp_patch.bcd_changed);

    let nv_payload = decompress_wpinternals_partition(SBA_COMPRESSED)?;
    ensure!(
        nv_payload.len().is_multiple_of(0x200),
        "SBA payload is not sector-aligned"
    );
    ensure!(
        (nv_payload.len() as u64) <= nv_update.uefi_bs_nv.sector_count() * SECTOR_SIZE,
        "SBA payload exceeds UEFI_BS_NV partition"
    );

    let (efiesp_first, efiesp_second_start_offset, efiesp_second) =
        build_spec_a_efiesp_payloads(&stock_efiesp, &patched_efiesp, efiesp_sector_count)?;
    let efiesp_second_sector = efiesp_partition
        .first_lba
        .checked_add(efiesp_second_start_offset)
        .context("EFIESP second payload start sector overflow")?;
    let efiesp_second_sector = u32::try_from(efiesp_second_sector)
        .context("EFIESP second payload start sector does not fit FlashApp NOKF")?;

    println!("write plan:");
    println!(
        "  UEFI_BS_NV start={} bytes={}",
        nv_first_sector,
        nv_payload.len()
    );
    if nv_update.gpt_changed {
        println!("  GPT start=0 bytes={}", nv_update.gpt.len());
    } else {
        println!("  GPT unchanged (BACKUP_BS_NV already present)");
    }
    println!(
        "  EFIESP reserved header start={} bytes={}",
        efiesp_first_sector,
        efiesp_first.len()
    );
    println!(
        "  EFIESP body start={} bytes={}",
        efiesp_second_sector,
        efiesp_second.len()
    );

    if dry_run {
        println!(
            "dry run: secure-boot disable artifacts built and validated; no sectors were written"
        );
        return Ok(());
    }

    println!("starting destructive secure-boot disable writes");
    with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::FlashApp, "disable-secure-boot")?;
        flash_raw_payload(
            handle,
            endpoints,
            "SBA payload to UEFI_BS_NV",
            nv_first_sector,
            &nv_payload,
            10,
            20,
        )?;
        if nv_update.gpt_changed {
            flash_raw_payload(handle, endpoints, "patched GPT", 0, &nv_update.gpt, 25, 30)?;
        }
        flash_raw_payload(
            handle,
            endpoints,
            "EFIESP body payload",
            efiesp_second_sector,
            &efiesp_second,
            35,
            95,
        )?;
        flash_raw_payload(
            handle,
            endpoints,
            "EFIESP reserved header payload",
            efiesp_first_sector,
            &efiesp_first,
            96,
            100,
        )?;
        Ok(())
    })?;

    println!("secure-boot disable writes completed");
    if no_reset {
        println!("left phone in FlashApp because --no-reset was set");
    } else {
        reset::run(vid, pid, false).context("writes completed, but reset failed")?;
    }

    Ok(())
}

fn flash_raw_payload(
    handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    endpoints: &crate::uefi::Endpoints,
    label: &str,
    start_sector: u32,
    data: &[u8],
    start_progress: u8,
    end_progress: u8,
) -> Result<()> {
    ensure!(!data.is_empty(), "{label} is empty");
    ensure!(
        data.len().is_multiple_of(SECTOR_SIZE as usize),
        "{label} is not sector-aligned"
    );
    ensure!(
        RAW_FLASH_CHUNK_SIZE.is_multiple_of(SECTOR_SIZE as usize),
        "raw flash chunk size is not sector-aligned"
    );

    let total_chunks = data.len().div_ceil(RAW_FLASH_CHUNK_SIZE);
    println!(
        "writing {label}: {} bytes in {total_chunks} chunk(s)",
        data.len()
    );

    for (index, chunk) in data.chunks(RAW_FLASH_CHUNK_SIZE).enumerate() {
        ensure!(
            chunk.len().is_multiple_of(SECTOR_SIZE as usize),
            "{label} chunk {} is not sector-aligned",
            index + 1
        );
        let sector_offset = u32::try_from(index * (RAW_FLASH_CHUNK_SIZE / SECTOR_SIZE as usize))
            .context("raw flash sector offset overflow")?;
        let chunk_start_sector = start_sector
            .checked_add(sector_offset)
            .context("raw flash start sector overflow")?;
        let progress = chunk_progress(index, total_chunks, start_progress, end_progress);
        println!(
            "  chunk {}/{} start={} bytes={}",
            index + 1,
            total_chunks,
            chunk_start_sector,
            chunk.len()
        );
        flash_raw_sectors(handle, endpoints, chunk_start_sector, chunk, progress)
            .with_context(|| format!("failed to write {label} chunk {}", index + 1))?;
    }

    Ok(())
}

fn chunk_progress(index: usize, total_chunks: usize, start_progress: u8, end_progress: u8) -> u8 {
    if total_chunks <= 1 {
        return end_progress;
    }
    let start = start_progress.min(end_progress) as usize;
    let end = end_progress.max(start_progress) as usize;
    let span = end - start;
    (start + span * index / (total_chunks - 1)).min(100) as u8
}

struct PhoneIdentity {
    product_type: String,
    product_code: String,
    imei: String,
}

fn read_phone_identity(vid: u16, pid: u16) -> Result<PhoneIdentity> {
    with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(
            app,
            LumiaApp::PhoneInfoApp,
            "disable-secure-boot phone identity read",
        )?;

        Ok(PhoneIdentity {
            product_type: read_phone_info_ascii(handle, endpoints, "TYPE")?,
            product_code: read_phone_info_ascii(handle, endpoints, "CTR")?,
            imei: read_phone_info_ascii(handle, endpoints, "IMEI")?,
        })
    })
}

fn read_phone_info_ascii(
    handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    endpoints: &crate::uefi::Endpoints,
    name: &str,
) -> Result<String> {
    let request = make_phone_info_read_request(name);
    let response = send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)?;
    let value = parse_phone_info_response(&response)?;
    let text = ascii_param_value(value)
        .with_context(|| format!("PhoneInfoApp {name} is not printable ASCII"))?;
    ensure!(!text.is_empty(), "PhoneInfoApp returned an empty {name}");
    Ok(text)
}

fn validate_preflight(
    ffu_path: &Path,
    ffu: &FfuMetadata,
    flash_info: &crate::flash::FlashAppInfo,
    phone_rrkh: &[u8],
    flash_version: &[u8],
    security_status: &[u8],
) -> Result<()> {
    validate_ffu_against_flash_app(ffu, flash_info)?;
    validate_flash_version(flash_version)?;
    validate_security_status(security_status)?;
    ensure!(
        phone_rrkh.len() == 32,
        "phone RRKH has unexpected length: {} bytes",
        phone_rrkh.len()
    );
    let sbl1 = ffu
        .get_partition(ffu_path, "SBL1")
        .context("failed to extract SBL1 from stock FFU for RRKH validation")?;
    let ffu_rrkh = extract_root_key_hash(&sbl1).context("failed to extract RRKH from FFU SBL1")?;
    ensure!(
        phone_rrkh == ffu_rrkh.as_slice(),
        "FFU SBL1 RRKH {} does not match phone RRKH {}",
        hex_dump_compact(&ffu_rrkh),
        hex_dump_compact(phone_rrkh)
    );
    println!("phone RRKH: {}", hex_dump_compact(phone_rrkh));
    println!("ffu SBL1 RRKH: {}", hex_dump_compact(&ffu_rrkh));
    println!("preflight validation passed");
    Ok(())
}

fn validate_flash_version(value: &[u8]) -> Result<()> {
    ensure!(value.len() >= 5, "FAI parameter is too short");
    let protocol_major = value[1];
    let protocol_minor = value[2];
    let app_major = value[3];
    let app_minor = value[4];
    ensure!(
        protocol_major < 2,
        "disable-secure-boot currently supports Spec A FlashApp only, but FlashApp protocol is {protocol_major}.{protocol_minor}"
    );
    ensure!(
        app_major > 1 || (app_major == 1 && app_minor >= 28),
        "disable-secure-boot requires FlashApp >= 1.28, but phone reports {app_major}.{app_minor}"
    );
    println!("flash protocol: {protocol_major}.{protocol_minor}");
    println!("flash app: {app_major}.{app_minor}");
    Ok(())
}

fn validate_security_status(value: &[u8]) -> Result<()> {
    ensure!(value.len() >= 8, "SS parameter is too short");
    let platform_secure_boot = value[1] != 0;
    let secure_ffu = value[2] != 0;
    let uefi_secure_boot = value[6] != 0;
    ensure!(
        !platform_secure_boot && !secure_ffu,
        "disable-secure-boot requires the Spec A jailbreak first; platform_secure_boot={platform_secure_boot} secure_ffu={secure_ffu}"
    );
    if !uefi_secure_boot {
        println!("UEFI secure boot already reports disabled");
    } else {
        println!("UEFI secure boot currently reports enabled");
    }
    Ok(())
}

fn read_live_gpt(
    handle: &mut rusb::DeviceHandle<rusb::GlobalContext>,
    endpoints: &crate::uefi::Endpoints,
) -> Result<Vec<u8>> {
    let app = identify_app(handle, endpoints)?;
    require_app(app, LumiaApp::FlashApp, "disable-secure-boot GPT read")?;
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
        gpt.len().is_multiple_of(0x200),
        "NOKT GPT payload is not sector-aligned: {} bytes",
        gpt.len()
    );
    Ok(gpt)
}

fn decompress_wpinternals_partition(bytes: &[u8]) -> Result<Vec<u8>> {
    let signature = b"\xffCompressedPartition\0";
    if !bytes.starts_with(signature) {
        return Ok(bytes.to_vec());
    }
    ensure!(
        bytes.len() >= signature.len() + 0x10,
        "compressed WPinternals asset header is truncated"
    );
    let version = u32::from_le_bytes(
        bytes[signature.len()..signature.len() + 4]
            .try_into()
            .unwrap(),
    );
    ensure!(
        version <= 1,
        "unsupported WPinternals compression version {version}"
    );
    let header_size = u32::from_le_bytes(
        bytes[signature.len() + 4..signature.len() + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    ensure!(
        header_size >= signature.len() + 0x10 && header_size <= bytes.len(),
        "invalid WPinternals compressed asset header size {header_size}"
    );
    let decompressed_len = u64::from_le_bytes(
        bytes[signature.len() + 8..signature.len() + 16]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut decoder = GzDecoder::new(&bytes[header_size..]);
    let mut result = Vec::with_capacity(decompressed_len);
    decoder
        .read_to_end(&mut result)
        .context("failed to decompress WPinternals asset")?;
    ensure!(
        result.len() == decompressed_len,
        "decompressed WPinternals asset length {} did not match header {decompressed_len}",
        result.len()
    );
    Ok(result)
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn mask_imei(imei: &str) -> String {
    let suffix_len = imei.len().min(4);
    let prefix_len = imei.len().saturating_sub(suffix_len);
    format!("{}{}", "*".repeat(prefix_len), &imei[prefix_len..])
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn decompresses_vendored_sba() {
        let decompressed = decompress_wpinternals_partition(SBA_COMPRESSED).unwrap();
        assert_eq!(decompressed.len(), 262144);
        let digest = Sha256::digest(&decompressed)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "a6f1f290b1672abbb5e0eb8bf4482e033f3dc4b428f1f3374e127e461d29c7c6"
        );
    }
}
