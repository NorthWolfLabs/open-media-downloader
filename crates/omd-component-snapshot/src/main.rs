//! Compiled to wasm32-wasip1 and bundled with the TypeScript SDK. The SDK grants
//! this build tool access only to ComponentizeJS's temporary build directory.
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(args.len() == 2, "Expected input and output core-WASM paths");
    let input = std::fs::read(&args[0])?;
    let output = omd_component_snapshot::deterministic_initialization(&input)?;
    std::fs::write(&args[1], output)?;
    Ok(())
}
