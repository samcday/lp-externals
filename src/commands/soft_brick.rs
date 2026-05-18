use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

use crate::{
    ffu::FfuMetadata,
    flash::soft_brick_with_ffu,
    uefi::{
        LumiaApp, ascii_param_value, identify_app, make_phone_info_read_request,
        parse_phone_info_response, require_app, send_raw_command,
        send_raw_command_allow_disconnect, switch_to_flash_app, switch_to_phone_info_app,
        with_device, with_device_allow_release_disconnect,
    },
};

pub(crate) fn run(
    vid: u16,
    pid: u16,
    wait: bool,
    ffu_path: &Path,
    confirm_imei: &str,
) -> Result<()> {
    ensure!(!confirm_imei.is_empty(), "--confirm-imei must not be empty");
    ensure!(confirm_imei.is_ascii(), "--confirm-imei must be ASCII");

    let ffu = FfuMetadata::open(ffu_path)
        .with_context(|| format!("failed to parse FFU {}", ffu_path.display()))?;
    println!("ffu path: {}", ffu_path.display());
    println!("ffu chunk size: {}", ffu.chunk_size);
    println!("ffu header size: {}", ffu.header_size);

    switch_to_phone_info_app(vid, pid, wait).context("failed to switch to PhoneInfoApp")?;
    let phone_imei = read_phone_info_imei(vid, pid)?;

    if phone_imei != confirm_imei {
        bail!(
            "IMEI confirmation mismatch: phone IMEI is {}, confirmation was {}. Soft-brick was not sent.",
            mask_imei(&phone_imei),
            mask_imei(confirm_imei)
        );
    }

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    let reset_ack_read =
        with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let app = identify_app(handle, endpoints)?;
            require_app(app, LumiaApp::FlashApp, "soft-brick")?;
            soft_brick_with_ffu(handle, endpoints, ffu_path, &ffu)?;
            send_raw_command_allow_disconnect(
                handle,
                endpoints.out_addr,
                endpoints.in_addr,
                b"NOKR",
            )
            .context("failed to send reset command after soft-brick payload")
        })?;

    println!("sent FlashApp soft-brick sequence");
    println!("confirmed phone IMEI: {}", mask_imei(&phone_imei));
    println!("sent reset command (NOKR)");
    if reset_ack_read {
        println!("received NOKR response; device may not have reset yet");
    }

    Ok(())
}

fn read_phone_info_imei(vid: u16, pid: u16) -> Result<String> {
    let request = make_phone_info_read_request("IMEI");
    let response = with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::PhoneInfoApp, "soft-brick IMEI check")?;
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)
    })?;

    let value = parse_phone_info_response(&response)?;
    let imei = ascii_param_value(value).context("PhoneInfoApp IMEI is not printable ASCII")?;
    ensure!(!imei.is_empty(), "PhoneInfoApp returned an empty IMEI");
    Ok(imei)
}

fn mask_imei(imei: &str) -> String {
    let suffix_len = imei.len().min(4);
    let prefix_len = imei.len().saturating_sub(suffix_len);
    format!("{}{}", "*".repeat(prefix_len), &imei[prefix_len..])
}
