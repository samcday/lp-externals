use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};

use crate::{
    ffu::FfuMetadata,
    flash::{
        read_flash_app_info, read_flash_param, soft_brick_with_ffu, validate_ffu_against_flash_app,
    },
    jailbreak::{build_jailbreak_artifacts, print_write_plan, render_write_plan},
    lumiadb::{
        cache_dir_for, cached_emergency_path, cached_ffu_path, cached_sbl3_path, download_file,
        fetch_lumiadb_database, make_exact_lumiadb_plan, print_lumiadb_plan,
    },
    qcom::{extract_root_key_hash, matching_armprg_loaders},
    uefi::{
        LumiaApp, ascii_param_value, identify_app, make_phone_info_read_request,
        parse_phone_info_response, require_app, send_raw_command,
        send_raw_command_allow_disconnect, switch_to_flash_app, switch_to_phone_info_app,
        with_device, with_device_allow_release_disconnect,
    },
    util::hex_dump_compact,
};

pub(crate) fn run(
    vid: u16,
    pid: u16,
    wait: bool,
    dry_run: bool,
    confirm_imei: Option<&str>,
) -> Result<()> {
    if let Some(confirm_imei) = confirm_imei {
        ensure!(!confirm_imei.is_empty(), "--confirm-imei must not be empty");
        ensure!(confirm_imei.is_ascii(), "--confirm-imei must be ASCII");
    } else if !dry_run {
        bail!("jailbreak is destructive; pass --confirm-imei <IMEI> or use --dry-run");
    }

    switch_to_phone_info_app(vid, pid, wait).context("failed to switch to PhoneInfoApp")?;
    let phone = read_phone_identity(vid, pid)?;
    println!("phone type: {}", phone.product_type);
    println!("product code: {}", phone.product_code);
    println!("imei: {}", mask_imei(&phone.imei));

    if let Some(confirm_imei) = confirm_imei {
        if phone.imei != confirm_imei {
            bail!(
                "IMEI confirmation mismatch: phone IMEI is {}, confirmation was {}. Jailbreak was not started.",
                mask_imei(&phone.imei),
                mask_imei(confirm_imei)
            );
        }
    }

    println!("fetching LumiaDB metadata");
    let database = fetch_lumiadb_database()?;
    let plan = make_exact_lumiadb_plan(&database, &phone.product_type, &phone.product_code)?;
    print_lumiadb_plan(&plan);

    let ffu_path = cached_ffu_path(&plan)?;
    let emergency_path = cached_emergency_path(&plan)?;
    let sbl3_path = cached_sbl3_path(&plan)?;
    ensure_parent(&ffu_path)?;
    ensure_parent(&emergency_path)?;
    ensure_parent(&sbl3_path)?;

    let runtime = tokio::runtime::Runtime::new().context("failed to create download runtime")?;
    runtime.block_on(download_file(&plan.ffu_url, &ffu_path))?;
    runtime.block_on(download_file(&plan.emergency_url, &emergency_path))?;
    runtime.block_on(download_file(&plan.sbl3_url, &sbl3_path))?;

    let ffu = FfuMetadata::open(&ffu_path)
        .with_context(|| format!("failed to parse FFU {}", ffu_path.display()))?;
    println!("ffu path: {}", ffu_path.display());
    println!("emergency path: {}", emergency_path.display());
    println!("engineering SBL3 path: {}", sbl3_path.display());
    println!("ffu platform: {}", ffu.platform_id);
    println!("ffu chunk size: {}", ffu.chunk_size);
    println!("ffu chunks: {}", ffu.total_chunk_count);

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    let (flash_info, phone_rrkh, flash_version, security_status) =
        with_device(vid, pid, false, |handle, endpoints| {
            let flash_info = read_flash_app_info(handle, endpoints)?;
            let phone_rrkh = read_flash_param(handle, endpoints, "RRKH")?;
            let flash_version = read_flash_param(handle, endpoints, "FAI")?;
            let security_status = read_flash_param(handle, endpoints, "SS")?;
            Ok((flash_info, phone_rrkh, flash_version, security_status))
        })?;

    validate_flash_version(&flash_version)?;
    validate_security_status(&security_status)?;
    validate_ffu_against_flash_app(&ffu, &flash_info)?;
    validate_rrkh(&ffu_path, &ffu, &phone_rrkh)?;

    let loaders = matching_armprg_loaders(&emergency_path, &phone_rrkh)
        .with_context(|| format!("failed to scan loaders in {}", emergency_path.display()))?;
    ensure!(
        !loaders.is_empty(),
        "no matching QHSUSB_ARMPRG loaders found for phone RRKH"
    );
    println!("matching emergency loaders: {}", loaders.len());
    for loader in &loaders {
        println!(
            "  {} format={} size={} rkh={}",
            loader.name,
            loader.format,
            loader.size,
            hex_dump_compact(&loader.root_key_hash)
        );
    }

    let artifacts = build_jailbreak_artifacts(&ffu_path, &ffu, &sbl3_path)?;
    let artifact_dir =
        cache_dir_for(&plan.device.hardware_model, &plan.firmware.product_code)?.join("jailbreak");
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("failed to create {}", artifact_dir.display()))?;
    fs::write(artifact_dir.join("gpt.bin"), &artifacts.patched_gpt)
        .with_context(|| format!("failed to write {}/gpt.bin", artifact_dir.display()))?;
    fs::write(artifact_dir.join("hack.bin"), &artifacts.hack_sector)
        .with_context(|| format!("failed to write {}/hack.bin", artifact_dir.display()))?;
    fs::write(artifact_dir.join("sbl2.bin"), &artifacts.patched_sbl2)
        .with_context(|| format!("failed to write {}/sbl2.bin", artifact_dir.display()))?;
    fs::write(artifact_dir.join("sbl3.bin"), &artifacts.patched_sbl3)
        .with_context(|| format!("failed to write {}/sbl3.bin", artifact_dir.display()))?;
    fs::write(artifact_dir.join("uefi.bin"), &artifacts.patched_uefi)
        .with_context(|| format!("failed to write {}/uefi.bin", artifact_dir.display()))?;
    fs::write(
        artifact_dir.join("write-plan.txt"),
        render_write_plan(&artifacts.write_plan),
    )
    .with_context(|| format!("failed to write {}/write-plan.txt", artifact_dir.display()))?;

    println!("patched artifacts:");
    println!("  directory: {}", artifact_dir.display());
    println!("  GPT: {} bytes", artifacts.patched_gpt.len());
    println!("  HACK: {} bytes", artifacts.hack_sector.len());
    println!("  SBL2: {} bytes", artifacts.patched_sbl2.len());
    println!("  SBL3: {} bytes", artifacts.patched_sbl3.len());
    println!("  UEFI: {} bytes", artifacts.patched_uefi.len());
    print_write_plan(&artifacts.write_plan);

    if dry_run {
        println!("dry run: jailbreak pre-EDL preflight passed; no phone state was written");
        return Ok(());
    }

    println!("starting destructive jailbreak soft-brick stage");
    let reset_ack_read =
        with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let app = identify_app(handle, endpoints)?;
            require_app(app, LumiaApp::FlashApp, "jailbreak soft-brick")?;
            soft_brick_with_ffu(handle, endpoints, &ffu_path, &ffu)?;
            send_raw_command_allow_disconnect(
                handle,
                endpoints.out_addr,
                endpoints.in_addr,
                b"NOKR",
            )
            .context("failed to send reset command after soft-brick payload")
        })?;

    println!("sent jailbreak soft-brick sequence");
    println!("sent reset command (NOKR)");
    if reset_ack_read {
        println!("received NOKR response; device may not have reset yet");
    }
    println!("jailbreak stopped before Qualcomm EDL protocol interactions");
    println!("continue with a separate EDL/ARMPRG implementation session");

    Ok(())
}

struct PhoneIdentity {
    product_type: String,
    product_code: String,
    imei: String,
}

fn read_phone_identity(vid: u16, pid: u16) -> Result<PhoneIdentity> {
    with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::PhoneInfoApp, "jailbreak phone identity read")?;
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

fn validate_flash_version(value: &[u8]) -> Result<()> {
    ensure!(
        value.len() >= 5,
        "FlashApp FAI parameter is too short: {} bytes",
        value.len()
    );
    let major = value[3];
    let minor = value[4];
    ensure!(
        major > 1 || (major == 1 && minor >= 28),
        "FlashApp version {major}.{minor} is too old for Spec A jailbreak"
    );
    println!("flash app version: {major}.{minor}");
    Ok(())
}

fn validate_security_status(value: &[u8]) -> Result<()> {
    ensure!(
        value.len() >= 8,
        "FlashApp SS parameter is too short: {} bytes",
        value.len()
    );
    println!("platform secure boot: {}", value[1] != 0);
    println!("secure FFU efuse: {}", value[2] != 0);
    println!("RDC: {}", value[4] != 0);
    println!("authenticated: {}", value[5] != 0);
    println!("UEFI secure boot: {}", value[6] != 0);
    ensure!(
        value[1] != 0,
        "platform secure boot is not enabled; unexpected state"
    );
    ensure!(
        value[2] != 0,
        "secure FFU efuse is not enabled; unexpected state"
    );
    ensure!(
        value[4] == 0,
        "RDC is already present; refusing first-pass jailbreak"
    );
    ensure!(
        value[5] == 0,
        "FlashApp is already authenticated; refusing first-pass jailbreak"
    );
    Ok(())
}

fn validate_rrkh(ffu_path: &Path, ffu: &FfuMetadata, phone_rrkh: &[u8]) -> Result<()> {
    ensure!(
        phone_rrkh.len() == 32,
        "phone RRKH has unexpected length: {} bytes",
        phone_rrkh.len()
    );
    let sbl1 = ffu
        .get_partition(ffu_path, "SBL1")
        .context("failed to extract SBL1 from stock FFU for RRKH validation")?;
    let ffu_rrkh = extract_root_key_hash(&sbl1).context("failed to extract RRKH from FFU SBL1")?;
    let all_zero = phone_rrkh.iter().all(|byte| *byte == 0);
    ensure!(
        all_zero || phone_rrkh == ffu_rrkh.as_slice(),
        "FFU SBL1 RRKH {} does not match phone RRKH {}",
        hex_dump_compact(&ffu_rrkh),
        hex_dump_compact(phone_rrkh)
    );
    println!("phone RRKH: {}", hex_dump_compact(phone_rrkh));
    println!("ffu SBL1 RRKH: {}", hex_dump_compact(&ffu_rrkh));
    Ok(())
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
