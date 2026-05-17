use anyhow::{Context, Result, bail, ensure};

use crate::uefi::{
    LumiaApp, ascii_param_value, identify_app, make_phone_info_read_request,
    parse_phone_info_response, require_app, send_raw_command, send_raw_command_expect_echo,
    switch_to_flash_app, switch_to_phone_info_app, with_device,
};

pub(crate) fn run(vid: u16, pid: u16, wait: bool, confirm_imei: &str) -> Result<()> {
    ensure!(!confirm_imei.is_empty(), "--confirm-imei must not be empty");
    ensure!(confirm_imei.is_ascii(), "--confirm-imei must be ASCII");

    switch_to_phone_info_app(vid, pid, wait).context("failed to switch to PhoneInfoApp")?;
    let phone_imei = read_phone_info_imei(vid, pid)?;

    if phone_imei != confirm_imei {
        bail!(
            "IMEI confirmation mismatch: phone IMEI is {}, confirmation was {}. Factory reset was not sent.",
            mask_imei(&phone_imei),
            mask_imei(confirm_imei)
        );
    }

    switch_to_flash_app(vid, pid, false).context("failed to switch to FlashApp")?;
    with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::FlashApp, "factory-reset")?;
        send_raw_command_expect_echo(handle, endpoints.out_addr, endpoints.in_addr, b"NOKG")
    })?;

    println!("sent FlashApp factory-reset command (NOKG)");
    println!("confirmed phone IMEI: {}", mask_imei(&phone_imei));
    Ok(())
}

fn read_phone_info_imei(vid: u16, pid: u16) -> Result<String> {
    let request = make_phone_info_read_request("IMEI");
    let response = with_device(vid, pid, false, |handle, endpoints| {
        let app = identify_app(handle, endpoints)?;
        require_app(app, LumiaApp::PhoneInfoApp, "factory-reset IMEI check")?;
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
