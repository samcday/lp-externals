use std::fs;

use anyhow::{Context, Result, bail, ensure};

use crate::{
    commands::reset,
    ffu::FfuMetadata,
    flash::{
        flash_signed_ffu, read_flash_app_info, read_flash_param, validate_ffu_against_flash_app,
    },
    lumiadb::{
        cached_ffu_path, download_file, fetch_lumiadb_database, make_exact_lumiadb_plan,
        print_lumiadb_plan,
    },
    qcom::extract_root_key_hash,
    uefi::{
        LumiaApp, ascii_param_value, identify_app, make_phone_info_read_request,
        parse_phone_info_response, require_app, send_raw_command, switch_to_flash_app,
        switch_to_phone_info_app, with_device,
    },
    util::hex_dump_compact,
};

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
        bail!("stock-restore is destructive; pass --confirm-imei <IMEI> or use --dry-run");
    }

    switch_to_phone_info_app(vid, pid, wait).context("failed to switch to PhoneInfoApp")?;
    let phone = read_phone_identity(vid, pid)?;
    println!("phone type: {}", phone.product_type);
    println!("product code: {}", phone.product_code);
    println!("imei: {}", mask_imei(&phone.imei));

    if let Some(confirm_imei) = confirm_imei {
        if phone.imei != confirm_imei {
            bail!(
                "IMEI confirmation mismatch: phone IMEI is {}, confirmation was {}. Stock restore was not started.",
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
    if let Some(parent) = ffu_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let runtime = tokio::runtime::Runtime::new().context("failed to create download runtime")?;
    runtime.block_on(download_file(&plan.ffu_url, &ffu_path))?;

    let ffu = FfuMetadata::open(&ffu_path)
        .with_context(|| format!("failed to parse FFU {}", ffu_path.display()))?;
    println!("ffu path: {}", ffu_path.display());
    println!("ffu size: {}", ffu.file_size);
    println!("ffu platform: {}", ffu.platform_id);
    println!("ffu chunk size: {}", ffu.chunk_size);
    println!(
        "ffu headers: security={} image={} store={} combined={}",
        ffu.security_header_len, ffu.image_header_len, ffu.store_header_len, ffu.header_size
    );
    println!("ffu chunks: {}", ffu.total_chunk_count);

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    let (flash_info, phone_rrkh) = with_device(vid, pid, false, |handle, endpoints| {
        let flash_info = read_flash_app_info(handle, endpoints)?;
        let phone_rrkh = read_flash_param(handle, endpoints, "RRKH")?;
        Ok((flash_info, phone_rrkh))
    })?;
    validate_preflight(&ffu_path, &ffu, &flash_info, &phone_rrkh)?;

    if dry_run {
        println!("dry run: stock restore preflight passed; no FFU data was written");
        return Ok(());
    }

    println!("starting destructive stock FFU restore");
    with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::FlashApp, "stock-restore")?;
        let flash_info = read_flash_app_info(handle, endpoints)?;
        validate_ffu_against_flash_app(&ffu, &flash_info)?;
        flash_signed_ffu(handle, endpoints, &ffu_path, &ffu, &flash_info)
    })?;

    println!("stock FFU restore completed");
    if no_reset {
        println!("left phone in FlashApp because --no-reset was set");
    } else {
        reset::run(vid, pid, false).context("stock restore completed, but reset failed")?;
    }

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
        require_app(
            app,
            LumiaApp::PhoneInfoApp,
            "stock-restore phone identity read",
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
    ffu_path: &std::path::Path,
    ffu: &FfuMetadata,
    flash_info: &crate::flash::FlashAppInfo,
    phone_rrkh: &[u8],
) -> Result<()> {
    validate_ffu_against_flash_app(ffu, flash_info)?;
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

fn mask_imei(imei: &str) -> String {
    let suffix_len = imei.len().min(4);
    let prefix_len = imei.len().saturating_sub(suffix_len);
    format!("{}{}", "*".repeat(prefix_len), &imei[prefix_len..])
}
