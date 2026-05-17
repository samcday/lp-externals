use anyhow::{Result, ensure};

use crate::{
    uefi::{send_raw_command, with_device},
    util::hex_dump,
};

pub(crate) fn run(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKD")
    })?;

    ensure!(
        response == b"NOKD",
        "unexpected NOKD response: {}",
        hex_dump(&response)
    );
    println!("disabled reboot timeout (NOKD)");
    Ok(())
}
