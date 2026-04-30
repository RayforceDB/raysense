use anyhow::Result;
use clap::{Parser, Subcommand};
use raysense_core::scan_path;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "raysense")]
#[command(about = "Local architectural telemetry for AI coding agents")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Observe {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Observe { path, json } => {
            let report = scan_path(path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_summary(&report);
            }
        }
    }

    Ok(())
}

fn print_summary(report: &raysense_core::ScanReport) {
    println!("snapshot {}", report.snapshot.snapshot_id);
    println!("root {}", report.snapshot.root.display());
    println!("files {}", report.snapshot.file_count);
    println!("functions {}", report.snapshot.function_count);
    println!("imports {}", report.snapshot.import_count);
    println!("resolved_edges {}", report.graph.resolved_edge_count);
    println!("cycles {}", report.graph.cycle_count);
    println!("max_fan_in {}", report.graph.max_fan_in);
    println!("max_fan_out {}", report.graph.max_fan_out);
}
