use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};
use lantern_comet_compat::verify_reference_json;

fn main() -> Result<()> {
    let fixture_path = env::args_os().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/cometbft-v0.38.23.json"),
        PathBuf::from,
    );
    let fixture = fs::read(&fixture_path)
        .with_context(|| format!("read fixture {}", fixture_path.display()))?;
    let evidence = verify_reference_json(&fixture).context("M5.0 compatibility gate failed")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).context("encode gate evidence")?
    );
    Ok(())
}
