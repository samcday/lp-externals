use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::{
    qcom::{
        QualcommImage, contains_utf16le, print_qcom_image, read_qcom_candidates, read_qcom_source,
    },
    util::{hex_dump_compact, parse_hex_bytes},
};

pub(crate) fn image_info(path: &Path, offset: u32) -> Result<()> {
    let source = read_qcom_source(path)?;
    let image = QualcommImage::parse(&source.bytes, offset)
        .with_context(|| format!("failed to parse Qualcomm image in {}", path.display()))?;

    println!("path: {}", path.display());
    println!("source format: {}", source.format);
    println!("source bytes: {}", source.bytes.len());
    print_qcom_image(&image);

    Ok(())
}

pub(crate) fn scan_loaders(path: &Path, rrkh: Option<&str>) -> Result<()> {
    let expected_rrkh = rrkh.map(parse_hex_bytes).transpose()?;
    if let Some(rrkh) = &expected_rrkh {
        ensure!(
            rrkh.len() == 0x20,
            "RRKH must be 32 bytes, got {}",
            rrkh.len()
        );
    }

    let candidates = read_qcom_candidates(path)?;
    ensure!(!candidates.is_empty(), "no loader candidates found");

    let mut matches = 0usize;
    for candidate in candidates {
        print!("{}: ", candidate.name);

        if candidate.bytes.len() > 0x80000 {
            println!("skip size={} (> 0x80000)", candidate.bytes.len());
            continue;
        }

        match QualcommImage::parse(&candidate.bytes, 0) {
            Ok(image) => {
                let armprg = contains_utf16le(&candidate.bytes, "QHSUSB_ARMPRG");
                let rkh_matches = expected_rrkh
                    .as_deref()
                    .is_none_or(|rrkh| image.root_key_hash.as_deref() == Some(rrkh));
                let status = if armprg && rkh_matches {
                    matches += 1;
                    "MATCH"
                } else {
                    "skip"
                };

                println!(
                    "{status} format={} size={} armprg={} rkh={}",
                    candidate.format,
                    candidate.bytes.len(),
                    armprg,
                    image
                        .root_key_hash
                        .as_deref()
                        .map(hex_dump_compact)
                        .unwrap_or_else(|| "none".to_string())
                );
            }
            Err(err) => println!("skip parse-error={err:#}"),
        }
    }

    println!("matching loaders: {matches}");

    Ok(())
}
