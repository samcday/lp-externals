use anyhow::{Result, ensure};

use crate::{
    uefi::{
        ascii_param_value, ensure_active_app, make_phone_info_read_request,
        parse_phone_info_response, print_raw_response, send_raw_command, with_device,
    },
    util::hex_dump,
};

pub(crate) fn read(vid: u16, pid: u16, wait: bool, debug: bool, name: &str) -> Result<()> {
    ensure!(
        name.len() <= 4,
        "variable name must be at most 4 ASCII bytes"
    );
    ensure!(name.is_ascii(), "variable name must be ASCII");

    let request = make_phone_info_read_request(name);
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        let identification =
            send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKV")?;
        ensure_active_app(&identification, 3, "PhoneInfoApp", "phone-info read")?;
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)
    })?;

    let value = parse_phone_info_response(&response)?;

    if debug {
        print_raw_response(&response);
    }

    println!("variable: {name}");
    println!("length: {} bytes", value.len());

    if debug {
        println!("hex: {}", hex_dump(value));
    }

    if let Some(text) = ascii_param_value(value) {
        println!("ascii: {text}");
    }

    Ok(())
}
