use anyhow::Result;

use crate::uefi::{print_identification, send_raw_command, with_device};

pub(crate) fn run(vid: u16, pid: u16, wait: bool, debug: bool) -> Result<()> {
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")
    })?;
    print_identification(&response, debug);
    Ok(())
}
