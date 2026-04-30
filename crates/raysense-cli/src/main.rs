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
        #[arg(long)]
        memory: bool,
    },
    RayforceVersion,
    Memory {
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Observe { path, json, memory } => {
            let report = scan_path(path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if memory {
                let memory = raysense_memory::RayMemory::from_report(&report)?;
                print_memory_summary(&memory.summary());
            } else {
                print_summary(&report);
            }
        }
        Command::RayforceVersion => {
            println!("{}", rayforce_sys::version_string());
        }
        Command::Memory { path } => {
            let report = scan_path(path)?;
            let memory = raysense_memory::RayMemory::from_report(&report)?;
            print_memory_summary(&memory.summary());
        }
    }

    Ok(())
}

fn print_memory_summary(summary: &raysense_memory::MemorySummary) {
    println!(
        "files rows={} cols={}",
        summary.files.rows, summary.files.columns
    );
    println!(
        "functions rows={} cols={}",
        summary.functions.rows, summary.functions.columns
    );
    println!(
        "imports rows={} cols={}",
        summary.imports.rows, summary.imports.columns
    );
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
