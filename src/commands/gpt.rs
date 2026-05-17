use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;

use crate::{
    gpt::print_gpt,
    uefi::{send_raw_command, with_device},
    util::{ascii_dump, hex_dump},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum DumpFormat {
    Text,
    RawHex,
}

impl fmt::Display for DumpFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::RawHex => write!(f, "raw-hex"),
        }
    }
}

pub(crate) fn dump(vid: u16, pid: u16, wait: bool, format: DumpFormat) -> Result<()> {
    let response = with_device(vid, pid, wait, |handle, endpoints| {
        send_raw_command(handle, endpoints.out_addr, endpoints.in_addr, b"NOKT")
    })?;

    ensure!(
        response.len() >= 8,
        "NOKT response too short: {} bytes",
        response.len()
    );

    if &response[..4] == b"NOKU" {
        bail!("device reported NOKT as unsupported");
    }

    ensure!(
        &response[..4] == b"NOKT",
        "unexpected NOKT response signature: {}",
        ascii_dump(&response[..response.len().min(4)])
    );

    let error = u16::from_be_bytes([response[6], response[7]]);
    ensure!(error == 0, "NOKT failed with error 0x{error:04x}");

    let gpt = response
        .get(8..)
        .context("NOKT response does not contain a GPT payload")?;

    match format {
        DumpFormat::Text => print_gpt(gpt),
        DumpFormat::RawHex => {
            println!("{}", hex_dump(gpt));
            Ok(())
        }
    }
}
