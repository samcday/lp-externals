use anyhow::{Context, Result, bail};

use crate::uefi::{
    RESET_RETRY_TIMEOUT, app_type_name, ensure_shutdown_supported_app, parse_nokv_app_type,
    send_raw_command, send_raw_command_expect_echo, send_raw_void_command,
    with_device_allow_release_disconnect,
};

const DEVICE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) fn run(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let app = with_device_allow_release_disconnect(vid, pid, wait, |handle, endpoints| {
        let identification =
            send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
        let app = parse_nokv_app_type(&identification)?;

        if app == 3 {
            send_raw_void_command(handle, endpoints.out_addr, b"NOKA")?;
        } else {
            ensure_shutdown_supported_app(app)?;
            send_raw_command_expect_echo(handle, endpoints.out_addr, endpoints.in_addr, b"NOKZ")?;
        }

        Ok(app)
    })?;

    if app == 3 {
        println!("PhoneInfoApp does not support NOKZ; sent continue-boot command (NOKA)");
        let next_app = send_when_available(vid, pid)?;

        println!(
            "sent shutdown command (NOKZ) after PhoneInfoApp continued to {}",
            app_type_name(next_app)
        );
        println!("Unplug device to complete shutdown.");
        return Ok(());
    }

    println!("sent shutdown command (NOKZ)");
    println!("Unplug device to complete shutdown.");

    Ok(())
}

fn send_when_available(vid: u16, pid: u16) -> Result<u8> {
    let started = std::time::Instant::now();
    let mut last_error = None;

    while started.elapsed() < RESET_RETRY_TIMEOUT {
        match with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let identification =
                send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
            let app = parse_nokv_app_type(&identification)?;
            ensure_shutdown_supported_app(app)?;
            send_raw_command_expect_echo(handle, endpoints.out_addr, endpoints.in_addr, b"NOKZ")?;
            Ok(app)
        }) {
            Ok(app) => return Ok(app),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(DEVICE_POLL_INTERVAL);
            }
        }
    }

    match last_error {
        Some(err) => Err(err).context("timed out waiting for shutdown-capable app after NOKA"),
        None => bail!("timed out waiting for shutdown-capable app after NOKA"),
    }
}
