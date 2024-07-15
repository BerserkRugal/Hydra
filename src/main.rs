#![feature(drain_filter)]
// TODO: metrics critical path to see what affects performance.

use crate::config_gen::DistributionPlan;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    cmp::{min,max},
};

use clap::Parser;
use cli::{Cli, Commands};
use consensus::VoterSet;
use crypto::generate_keypairs;
use network::{FailureNetwork, MemoryNetwork, TcpNetwork};
use node::Node;

use anyhow::Result;

mod cli;
mod client;
mod config_gen;
mod consensus;
mod crypto;
mod data;
mod mempool;
mod metrics;
mod network;
mod node;
mod node_config;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = crate::node_config::NodeConfig::from_cli(&cli)?;

    tracing_subscriber::fmt::init();

    match cli.command {
        Some(Commands::MemoryTestJoin { number, initial_number, sequential_join }) => {
            let voter_set: Vec<_> = generate_keypairs(number);
            let inum = min(number, initial_number);
            let lnum = 1 + ((((number as f64  / 3.0).floor()-1.0)/2.0).floor() as usize);
            let inum = max(inum, lnum);
            let initial_set: Vec<_> = voter_set.iter().take(inum).cloned().collect();
            let rest_set: Vec<_> = voter_set.iter().filter(|&element| !initial_set.contains(element)).cloned().collect();
            let l_set: Vec<_> = voter_set.iter().take(lnum).cloned().collect();
            let genesis = data::Block::genesis();

            let mut network = MemoryNetwork::new();
            config.test_mode.memory_test_join = true;

            // Mock peers
            config.override_voter_set(&VoterSet::new(
                voter_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_initial_members(&VoterSet::new(
              initial_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_l(&VoterSet::new(
              l_set.iter().map(|(pk, _)| *pk).collect(),
            ));


            // Prepare the environment.
            let nodes: Vec<_> = initial_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();

             let rest_nodes: Vec<_> = rest_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();    

            // Boot up the network.
            let handle = tokio::spawn(async move {
                network.dispatch().await?;
                Ok::<_, anyhow::Error>(())
            });

            nodes.get(0).unwrap().metrics();

            // Run the nodes.
            nodes.into_iter().for_each(|node| {
                node.spawn_run();
            });
            if sequential_join == false {
               rest_nodes.into_iter().for_each(|node| {
                  node.spawn_run_membership_test(1,5000);
               });
            }else{
              let mut delay_time = 5000;
              rest_nodes.into_iter().for_each(|node| {
                node.spawn_run_membership_test(1, delay_time);
                delay_time = delay_time + 5000;
             });
            }

            let _ = tokio::join!(handle);
        }
        Some(Commands::MemoryTestLeave { number, leave_number, sequential_leave }) => {
            let voter_set: Vec<_> = generate_keypairs(number);
            let inum = min(number, leave_number);
            let lnum = 1 + ((((number as f64  / 3.0).floor()-1.0)/2.0).floor() as usize);
            let inum = max(number-inum, lnum);
            let final_set: Vec<_> = voter_set.iter().take(inum).cloned().collect();
            let rest_set: Vec<_> = voter_set.iter().filter(|&element| !final_set.contains(element)).cloned().collect();
            let l_set: Vec<_> = voter_set.iter().take(lnum).cloned().collect();
            let genesis = data::Block::genesis();

            let mut network = MemoryNetwork::new();
            config.test_mode.memory_test_leave = true;

            // Mock peers
            config.override_voter_set(&VoterSet::new(
                voter_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_initial_members(&VoterSet::new(
              voter_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_l(&VoterSet::new(
              l_set.iter().map(|(pk, _)| *pk).collect(),
            ));


            // Prepare the environment.
            let nodes: Vec<_> = final_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();

             let rest_nodes: Vec<_> = rest_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();    

            // Boot up the network.
            let handle = tokio::spawn(async move {
                network.dispatch().await?;
                Ok::<_, anyhow::Error>(())
            });

            nodes.get(0).unwrap().metrics();

            // Run the nodes.
            nodes.into_iter().for_each(|node| {
                node.spawn_run();
            });
            if sequential_leave == false {
               rest_nodes.into_iter().for_each(|node| {
                  node.spawn_run_membership_test(2, 5000);
               });
            }else{
              let mut delay_time = 5000;
              rest_nodes.into_iter().for_each(|node| {
                node.spawn_run_membership_test(2, delay_time);
                delay_time = delay_time + 5000;
             });
            }

            let _ = tokio::join!(handle);
         }
         Some(Commands::MemoryTestHybrid { number, initial_number, leave_number, sequential}) => {
            let voter_set: Vec<_> = generate_keypairs(number);
            let inum = min(number, initial_number);
            let jnum = min(initial_number, leave_number);
            let lnum = 1 + ((((number as f64  / 3.0).floor()-1.0)/2.0).floor() as usize);
            let inum = max(inum, lnum);
            let jnum = max(initial_number-jnum, lnum);
            let initial_set: Vec<_> = voter_set.iter().take(inum).cloned().collect();
            let fixed_set: Vec<_> = initial_set.iter().take(jnum).cloned().collect();
            let leave_set: Vec<_> = initial_set.iter().filter(|&element| !fixed_set.contains(element)).cloned().collect();
            let join_set: Vec<_> = voter_set.iter().filter(|&element| !initial_set.contains(element)).cloned().collect();
            let l_set: Vec<_> = voter_set.iter().take(lnum).cloned().collect();
            let genesis = data::Block::genesis();

            let mut network = MemoryNetwork::new();
            config.test_mode.memory_test_hybrid = true;

            // Mock peers
            config.override_voter_set(&VoterSet::new(
                voter_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_initial_members(&VoterSet::new(
              initial_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_l(&VoterSet::new(
              l_set.iter().map(|(pk, _)| *pk).collect(),
            ));


            // Prepare the environment.
            let fixed_nodes: Vec<_> = fixed_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();

             let join_nodes: Vec<_> = join_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();
                
             let leave_nodes: Vec<_> = leave_set
                .into_iter()
                .map(|(id, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, secret),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();    

            // Boot up the network.
            let handle = tokio::spawn(async move {
                network.dispatch().await?;
                Ok::<_, anyhow::Error>(())
            });

            fixed_nodes.get(0).unwrap().metrics();

            // Run the nodes.
            fixed_nodes.into_iter().for_each(|node| {
                node.spawn_run();
            });
            if sequential == false {
               let mut delay_time = 5000;
               join_nodes.into_iter().for_each(|node| {
                  node.spawn_run_membership_test(3, delay_time);
                  delay_time = delay_time + 5000;
               });
               delay_time = 5000;
               leave_nodes.into_iter().for_each(|node| {
                node.spawn_run_membership_test(4, delay_time);
                delay_time = delay_time + 5000;
             });
            }else{
              let mut delay_time = 5000;
               join_nodes.into_iter().for_each(|node| {
                  node.spawn_run_membership_test(3, delay_time);
                  delay_time = delay_time + 10000;
               });
               delay_time = 10000;
               leave_nodes.into_iter().for_each(|node| {
                node.spawn_run_membership_test(4, delay_time);
                delay_time = delay_time + 10000;
             });
            }

            let _ = tokio::join!(handle);


         }
        Some(Commands::FailTest { number, fault }) => {
            // let total = number * 3 + 1;
            // let voter_set: Vec<_> = generate_keypairs(total);
            let voter_set: Vec<_> = generate_keypairs(number);
            let lnum = 1 + ((((number as f64  / 3.0).floor()-1.0)/2.0).floor() as usize);
            let l_set: Vec<_> = voter_set.iter().take(lnum).cloned().collect();
            let f = min(number-lnum, fault);
            let genesis = data::Block::genesis();
            let mut network = MemoryNetwork::new();

            // Mock peers
            config.override_voter_set(&VoterSet::new(
                voter_set.clone().iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_initial_members(&VoterSet::new(
              voter_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.override_l(&VoterSet::new(
              l_set.iter().map(|(pk, _)| *pk).collect(),
            ));
            config.test_mode.fault_test = true;
            // Prepare the environment.
            let nodes: Vec<_> = voter_set
                .iter()
                .enumerate()
                .filter_map(|(idx, (p, sec))| {
                    // if idx % 3 == 1 {
                    //     // Fail the node.
                    //     None
                    // } 
                    if idx >= number - f {
                        // Fail the node.
                        None
                    } 
                    else {
                        let adaptor = network.register(*p);
                        Some(Node::new(
                            config.clone_with_keypair(*p, sec.clone()),
                            adaptor,
                            genesis.to_owned(),
                        ))
                    }
                })
                .collect();

            // Boot up the network.
            let handle = tokio::spawn(async move {
                network.dispatch().await?;
                Ok::<_, anyhow::Error>(())
            });

            nodes.get(0).unwrap().metrics();

            // Run the nodes.
            nodes.into_iter().for_each(|node| {
                node.spawn_run();
            });

            let _ = tokio::join!(handle);
        }
        Some(Commands::ConfigGen {
            number,
            initial_number,
            mut hosts,
            mut export_dir,
            write_file,
            failure_nodes,
            auto_naming,
        }) => {
            if !auto_naming && export_dir.is_none() {
                panic!("export_dir must be specified when auto_naming is false");
            } else if auto_naming && export_dir.is_none() {
                let mut i = 0;
                while Path::new(&format!("config_{}", i)).exists() {
                    i += 1;
                }

                let name = format!("config_{}", i);

                export_dir = Some(PathBuf::from(name));
            }

            let export_dir = export_dir.expect("export_dir must be specified");

            // println!("Generating config {:?}", cfg);
            if hosts.is_empty() {
                println!("No hosts provided, use localhost instead.");
                hosts.push(String::from("localhost"))
            }

            let distribution_plan = DistributionPlan::new(number, initial_number, hosts, config, failure_nodes);

            if !write_file {
                for (path, content) in distribution_plan.dry_run(&export_dir)? {
                    println!("{}", path.display());
                    println!("{}", content);
                }
            } else {
                if !Path::new(&export_dir).is_dir() {
                    fs::create_dir_all(&export_dir)?;
                }

                for (path, content) in distribution_plan.dry_run(&export_dir)? {
                    let dir = path.parent().unwrap();
                    if !dir.exists() {
                        fs::create_dir(dir)?;
                    }
                    let mut file = File::create(path)?;
                    file.write_all(content.as_bytes())?;
                }
            }
        }
        None => {
            let adapter = if config.get_node_settings().pretend_failure {
                FailureNetwork::spawn(config.get_local_addr()?.to_owned(), config.get_peer_addrs())
            } else {
                TcpNetwork::spawn(config.get_local_addr()?.to_owned(), config.get_peer_addrs())
            };

            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

            let node = Node::new(config, adapter, data::Block::genesis());

            if !cli.disable_metrics {
                node.metrics();
            }

            // Run the node
            let handle = node.spawn_run();

            let _ = handle.await;
        }
    }
    Ok(())
}

//test
#[cfg(test)]
mod test {}
