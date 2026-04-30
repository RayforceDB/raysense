# Raysense

Raysense is local architectural telemetry for AI coding agents.

The crate exposes the owned scanner and architectural fact model.

```rust
let report = raysense::scan_path(".")?;
println!("files: {}", report.files.len());
# Ok::<(), raysense::ScanError>(())
```
