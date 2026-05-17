use anyhow::Result;

use crate::uefi::{switch_to_flash_app, switch_to_phone_info_app};

pub(crate) fn flash(vid: u16, pid: u16, wait: bool) -> Result<()> {
    switch_to_flash_app(vid, pid, wait)?;
    println!("phone is in FlashApp");
    Ok(())
}

pub(crate) fn phone_info(vid: u16, pid: u16, wait: bool) -> Result<()> {
    switch_to_phone_info_app(vid, pid, wait)?;
    println!("phone is in PhoneInfoApp");
    Ok(())
}
