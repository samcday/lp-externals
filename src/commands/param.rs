use anyhow::{Result, ensure};

use crate::{
    uefi::{
        ascii_param_value, make_read_param_request, parse_param_response, print_known_param_decode,
        print_raw_response, send_raw_command, with_device,
    },
    util::hex_dump,
};

pub(crate) fn read(vid: u16, pid: u16, wait: bool, debug: bool, name: &str) -> Result<()> {
    ensure!(
        name.len() <= 4,
        "parameter name must be at most 4 ASCII bytes"
    );
    ensure!(name.is_ascii(), "parameter name must be ASCII");

    let request = make_read_param_request(name);
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, &request)
    })?;

    let value = parse_param_response(&response)?;

    if debug {
        print_raw_response(&response);
    }

    println!("param: {name}");
    println!("length: {} bytes", value.len());

    if debug {
        println!("hex: {}", hex_dump(value));
    }

    if let Some(text) = ascii_param_value(value) {
        println!("ascii: {text}");
    }

    print_known_param_decode(name, value);
    Ok(())
}
