use anyhow::Result;

use crate::edl;

pub(crate) fn probe(vid: u16, pid: u16, wait: bool) -> Result<()> {
    let info = edl::probe(vid, pid, wait)?;

    println!("usb: {:04x}:{:04x}", vid, pid);
    println!("location: bus {} device {}", info.bus, info.address);
    println!(
        "manufacturer: {}",
        info.manufacturer.as_deref().unwrap_or("unknown")
    );
    println!("product: {}", info.product.as_deref().unwrap_or("unknown"));
    println!("mode: {}", info.mode.name());
    println!("interface: {}", info.endpoints.interface);
    println!("bulk in: 0x{:02x}", info.endpoints.in_addr);
    println!("bulk out: 0x{:02x}", info.endpoints.out_addr);

    Ok(())
}
