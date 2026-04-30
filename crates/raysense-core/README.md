# Raysense Core

Core scanner and architectural fact model for Raysense.

```rust
let report = raysense_core::scan_path(".")?;
println!("imports: {}", report.imports.len());
# Ok::<(), raysense_core::ScanError>(())
```
