use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::lumiadb::{
    download_file, fetch_lumiadb_database, http_client, make_lumiadb_plan, print_lumiadb_plan,
};

pub(crate) fn search(query: &str) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let normalized = query.to_lowercase();
    let mut matches = 0usize;

    for device in database.iter().filter(|device| device.matches(&normalized)) {
        matches += 1;
        println!(
            "{} - {} ({})",
            device.hardware_model, device.phone_model, device.variant
        );
        if !device.product_codes.is_empty() {
            println!("  product codes: {}", device.product_codes.join(", "));
        }
        for firmware in &device.firmwares {
            println!(
                "  {} {} product={} file={}",
                firmware.firmware,
                firmware.os.as_deref().unwrap_or("unknown OS"),
                firmware.product_code,
                firmware.ffu_filename
            );
        }
    }

    if matches == 0 {
        println!("no LumiaDB entries matched {query}");
    }

    Ok(())
}

pub(crate) fn plan(model: &str, product_code: Option<&str>) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let plan = make_lumiadb_plan(&database, model, product_code)?;
    print_lumiadb_plan(&plan);
    Ok(())
}

pub(crate) fn check(model: &str, product_code: Option<&str>) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let plan = make_lumiadb_plan(&database, model, product_code)?;
    let client = http_client()?;

    print_lumiadb_plan(&plan);
    println!();
    println!("availability:");

    for blob in plan.blobs() {
        let response = client
            .head(&blob.url)
            .send()
            .with_context(|| format!("HEAD failed for {}", blob.url))?;
        let status = response.status();
        let size = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown");
        println!("  {}: {} size={}", blob.kind, status, size);
    }

    Ok(())
}

pub(crate) fn download(model: &str, product_code: Option<&str>, output: &Path) -> Result<()> {
    let database = fetch_lumiadb_database()?;
    let plan = make_lumiadb_plan(&database, model, product_code)?;
    let target_dir = output
        .join(&plan.device.hardware_model)
        .join(&plan.firmware.product_code);

    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    print_lumiadb_plan(&plan);
    println!();
    println!("download directory: {}", target_dir.display());

    let runtime = tokio::runtime::Runtime::new().context("failed to create download runtime")?;
    for blob in plan.blobs() {
        let path = target_dir.join(blob.filename);
        runtime.block_on(download_file(&blob.url, &path))?;
    }

    let manifest = plan.manifest_json();
    fs::write(target_dir.join("manifest.json"), manifest)
        .with_context(|| format!("failed to write manifest in {}", target_dir.display()))?;

    Ok(())
}
