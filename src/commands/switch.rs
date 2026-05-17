use anyhow::Result;

use crate::uefi::{send_raw_void_command, with_device};

pub(crate) fn flash(vid: u16, pid: u16, wait: bool) -> Result<()> {
    with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_void_command(handle, endpoints.out_addr, b"NOKS")
    })?;
    println!("sent switch-to-FlashApp command (NOKS)");
    Ok(())
}

pub(crate) fn phone_info(vid: u16, pid: u16, wait: bool) -> Result<()> {
    with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_void_command(handle, endpoints.out_addr, b"NOKP")
    })?;
    println!("sent switch-to-PhoneInfoApp command (NOKP)");
    Ok(())
}
