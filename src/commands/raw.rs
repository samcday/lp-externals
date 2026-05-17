use anyhow::Result;

use crate::uefi::{print_raw_response, send_raw_command, with_device};

pub(crate) fn run(vid: u16, pid: u16, wait: bool, commands: &[String]) -> Result<()> {
    let responses = with_device(vid, pid, wait, |handle, endpoints| {
        let mut responses = Vec::with_capacity(commands.len());

        for command in commands {
            responses.push((
                command.clone(),
                send_raw_command(
                    handle,
                    endpoints.out_addr,
                    endpoints.in_addr,
                    command.as_bytes(),
                )?,
            ));
        }

        Ok(responses)
    })?;

    for (index, (command, response)) in responses.iter().enumerate() {
        if responses.len() > 1 {
            println!("command {}: {command}", index + 1);
        }
        print_raw_response(response);
    }

    Ok(())
}
