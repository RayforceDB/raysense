use anyhow::Result;
use clap::{Parser, Subcommand};
use raysense_core::{compute_health, scan_path, ImportResolution};
use std::io::{self, Write};
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
    Health {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Edges {
        path: PathBuf,
        #[arg(long)]
        all: bool,
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
        Command::Health { path, json } => {
            let report = scan_path(path)?;
            let health = compute_health(&report);
            if json {
                println!("{}", serde_json::to_string_pretty(&health)?);
            } else {
                print_health(&report, &health);
            }
        }
        Command::Edges { path, all } => {
            let report = scan_path(path)?;
            print_edges(&report, all)?;
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
    let health = compute_health(report);
    println!("snapshot {}", report.snapshot.snapshot_id);
    println!("root {}", report.snapshot.root.display());
    println!("score {}", health.score);
    println!("files {}", report.snapshot.file_count);
    println!("functions {}", report.snapshot.function_count);
    println!("imports {}", report.snapshot.import_count);
    println!("local_imports {}", health.resolution.local);
    println!("external_imports {}", health.resolution.external);
    println!("system_imports {}", health.resolution.system);
    println!("unresolved_imports {}", health.resolution.unresolved);
    println!("resolved_edges {}", report.graph.resolved_edge_count);
    println!("cycles {}", report.graph.cycle_count);
    println!("max_fan_in {}", report.graph.max_fan_in);
    println!("max_fan_out {}", report.graph.max_fan_out);
}

fn print_health(report: &raysense_core::ScanReport, health: &raysense_core::HealthSummary) {
    println!("score {}", health.score);
    println!("root {}", report.snapshot.root.display());
    println!(
        "facts files={} functions={} imports={}",
        report.snapshot.file_count, report.snapshot.function_count, report.snapshot.import_count
    );
    println!(
        "imports local={} external={} system={} unresolved={}",
        health.resolution.local,
        health.resolution.external,
        health.resolution.system,
        health.resolution.unresolved
    );
    println!(
        "graph resolved_edges={} cycles={} max_fan_in={} max_fan_out={}",
        report.graph.resolved_edge_count,
        report.graph.cycle_count,
        report.graph.max_fan_in,
        report.graph.max_fan_out
    );

    if !health.hotspots.is_empty() {
        println!("hotspots");
        for hotspot in &health.hotspots {
            println!(
                "  fan_in={} fan_out={} {}",
                hotspot.fan_in, hotspot.fan_out, hotspot.path
            );
        }
    }
}

fn print_edges(report: &raysense_core::ScanReport, all: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for import in &report.imports {
        if !all && import.resolution != ImportResolution::Local {
            continue;
        }

        let from = report
            .files
            .get(import.from_file)
            .map(|file| file.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("#{}", import.from_file));
        let to = import
            .resolved_file
            .and_then(|file_id| report.files.get(file_id))
            .map(|file| file.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| import.target.clone());

        if let Err(err) = writeln!(
            stdout,
            "{:?} {} -> {} ({})",
            import.resolution, from, to, import.kind
        ) {
            if err.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(err);
        }
    }

    Ok(())
}
