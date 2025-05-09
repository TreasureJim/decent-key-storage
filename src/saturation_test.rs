use csv::Writer;
use rand::{rngs::ThreadRng, seq::IndexedRandom};
use std::path::{Path, PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    number_of_clients: usize,
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run_simulations(&args.output) {
        eprintln!("Error: {}", e);
    } else {
        println!("Simulation complete. CSV files written.");
    }
}


fn run_simulations(folder: &Path) -> anyhow::Result<()> {
    let ratios = (0..=100).map(|n| n as f64 / 100.0).collect::<Vec<_>>();
    let node_lengths = (2..=50).map(|n| n * 2 - 1).collect::<Vec<_>>();
    let ns = (1..=50).map(|n| n * 2 - 1).collect::<Vec<_>>();
    let runs_per_config = 1000;

    let mut wtr = Writer::from_path(folder.join("results.csv"))?;
    wtr.write_record(&["node_len", "n", "ratio_good", "accepted_good_pct", "detected_anomaly_pct"])?;
    for (i, ratio) in ratios.iter().enumerate() {
        println!("{i} out of {}", ratios.len());

        for &node_len in &node_lengths {
            let nodes = simulate_good_bad_nodes(node_len, *ratio);
            let mut rng = rand::rng();

            for &n in &ns {
                if n > node_len {
                    continue;
                }

                let mut accepted_good_count = 0;
                let mut detected_anomaly_count = 0;

                for _ in 0..runs_per_config {
                    let res = run_test(&mut rng, &nodes, n);
                    if res.accepted_good {
                        accepted_good_count += 1;
                    }
                    if res.detected_anomaly {
                        detected_anomaly_count += 1;
                    }
                }

                let accepted_good_pct = accepted_good_count as f64 / runs_per_config as f64;
                let detected_anomaly_pct = detected_anomaly_count as f64 / runs_per_config as f64;

                wtr.write_record(&[
                    node_len.to_string(),
                    n.to_string(),
                    ratio.to_string(),
                    format!("{:.3}", accepted_good_pct),
                    format!("{:.3}", detected_anomaly_pct),
                ])?;
            }
        }

        wtr.flush()?;
    }

    Ok(())
}


fn simulate_good_bad_nodes(number_of_clients: usize, ratio_good: f64) -> Vec<bool> {
    let num_good_clients = (number_of_clients as f64 * ratio_good).round() as usize;
    let num_bad_clients = number_of_clients - num_good_clients;

    let mut v = vec![true; num_good_clients];
    v.append(&mut vec![false; num_bad_clients]);
    v
}

struct TestResult {
    accepted_good: bool,
    detected_anomaly: bool
}

// accepted good key - bool
// detected anomaly - bool
// If accepted bad key and detected anomaly - that means it thinks that the good key was the
// anomaly (thinks good is bad)
fn run_test(rng: &mut ThreadRng, nodes: &[bool], n: usize) -> TestResult {
    assert!(nodes.len() >= n, "node length: {}, n: {}", nodes.len(), n);
    assert!(n % 2 == 1);

    let good = nodes.choose_multiple(rng, n).into_iter().fold(0, |acc, b| acc + *b as usize );
    let bad = n.checked_sub(good).unwrap();

    if good > bad {
        TestResult {
            accepted_good: true,
            detected_anomaly: bad > 0
        }
    } else {
        TestResult {
            accepted_good: false,
            detected_anomaly: good > 0
        }
    }
}
