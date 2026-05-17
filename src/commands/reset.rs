use anyhow::{Context, Result, bail};

use crate::uefi::{
    RESET_RETRY_TIMEOUT, app_type_name, ensure_reset_supported_app, parse_nokv_app_type,
    send_raw_command, send_raw_command_allow_disconnect, send_raw_void_command,
    with_device_allow_release_disconnect,
};

const DEVICE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) fn run(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let (app, ack_read) =
        with_device_allow_release_disconnect(vid, pid, wait, |handle, endpoints| {
            let identification =
                send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
            let app = parse_nokv_app_type(&identification)?;

            let mut ack_read = false;
            if app == 3 {
                send_raw_void_command(handle, endpoints.out_addr, b"NOKA")?;
            } else {
                ensure_reset_supported_app(app)?;
                ack_read = send_raw_command_allow_disconnect(
                    handle,
                    endpoints.out_addr,
                    endpoints.in_addr,
                    b"NOKR",
                )?;
            }

            Ok((app, ack_read))
        })?;

    if app == 3 {
        println!("PhoneInfoApp does not support NOKR; sent continue-boot command (NOKA)");
        let (next_app, ack_read) = send_when_available(vid, pid)?;

        println!(
            "sent reset command (NOKR) after PhoneInfoApp continued to {}",
            app_type_name(next_app)
        );
        if ack_read {
            println!("received NOKR response; device may not have reset");
        }
        return Ok(());
    }

    println!("sent reset command (NOKR)");
    if ack_read {
        println!("received NOKR response; device may not have reset");
    }

    Ok(())
}

fn send_when_available(vid: u16, pid: u16) -> Result<(u8, bool)> {
    let started = std::time::Instant::now();
    let mut last_error = None;

    while started.elapsed() < RESET_RETRY_TIMEOUT {
        match with_device_allow_release_disconnect(vid, pid, false, |handle, endpoints| {
            let identification =
                send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
            let app = parse_nokv_app_type(&identification)?;
            ensure_reset_supported_app(app)?;
            let ack_read = send_raw_command_allow_disconnect(
                handle,
                endpoints.out_addr,
                endpoints.in_addr,
                b"NOKR",
            )?;
            Ok((app, ack_read))
        }) {
            Ok(result) => return Ok(result),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(DEVICE_POLL_INTERVAL);
            }
        }
    }

    match last_error {
        Some(err) => Err(err).context("timed out waiting for reset-capable app after NOKA"),
        None => bail!("timed out waiting for reset-capable app after NOKA"),
    }
}
