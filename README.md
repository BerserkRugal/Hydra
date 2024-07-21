# Hydra

## Quick Start (Runs in debug mode by default)

Directly executing a binary will start a committee composed of a single node using localhost TCP for communication.

```Bash
cargo r
```

You can run

```Bash
cargo r -- -h
```

to get a complete definition of the command line parameters.

## Qucik test under Memory Network
#### Single replica via TCP:

```Bash
cargo run
```

#### Replica join test：

The subcommand `memory-test-join` is used to perform a join test of replicas: fewer than or equal to the total number of replicas are in the initial configuration, then consensus starts and the remaining replicas join after a period of time by initiating join requests sequentially (or simultaneously). Information about consensus membership changes, throughput and latency will be printed on the console.

Please lookup the document of `memory-test-join` before using it.

```Bash
cargo r -- memory-test-join -h
```

For example let's say you want to set the total number of replicas to 10, with 7 replicas in the initial configuration. Replicas send join requests to join in sequence.

```Bash
cargo r -- memory-test-join -n 10 -i 7 -s
```

Due to the existence of the L set, the number of replicas in any configuration must be greater than or equal to |L| - please note this when setting the parameters.

(View more specific logs, including proof construction and changes in voting thresholds, etc., by adding 'RUST_LOG=TRACE' to execution)

#### Replica leave test：

The subcommand `memory-test-leave` is used to perform a leave test of replicas: All replicas are in the initial configuration, then consensus starts and some replicas leave after a period of time by initiating leave requests sequentially (or simultaneously). Information about consensus membership changes, throughput and latency will be printed on the console.

Please lookup the document of `memory-test-leave` before using it.

```Bash
cargo r -- memory-test-leave -h
```

For example let's say you want to set the total number of replicas to 10, with 3 replicas to leave later. Replicas send leave requests to leave in sequence.

```Bash
cargo r -- memory-test-leave -n 10 -l 3 -s
```

Due to the existence of the L set, the number of replicas in any configuration must be greater than or equal to |L| - please note this when setting the parameters.

(View more specific logs, including proof construction and changes in voting thresholds, etc., by adding 'RUST_LOG=TRACE' to execution)

#### Hybrid test：

The subcommand `memory-test-hybrid` is used to perform a hybrid membership test of replicas: fewer than or equal to the total number of replicas are in the initial configuration, then consensus starts. After a period of time, the remaining replicas join by initiating join requests, also some replicas leave by initiating leave requests. The requests can be initiated sequentially (or simultaneously). Information about consensus membership changes, throughput and latency will be printed on the console.

Please lookup the document of `memory-test-hybrid` before using it.

```Bash
cargo r -- memory-test-hybrid -h
```

For example let's say you want to set the total number of replicas to 10, with 7 replicas in the initial configuration and 3 replicas to leave later. Replicas send leave requests to leave in sequence.

```Bash
cargo r -- memory-test-hybrid -n 10 -i 7 -l 3 -s
```

Due to the existence of the L set, the number of replicas in any configuration must be greater than or equal to |L| - please note this when setting the parameters.

(View more specific logs, including proof construction and changes in voting thresholds, etc., by adding 'RUST_LOG=TRACE' to execution)

### Failure test

The subcommand `fail-test` is used to perform a fault tolerant test: running consensus in the presence of some faulty replicas. In Hydra, it is mainly used to test the configuration auto-transition protocol (please set the faults to be not less than 1/3 of the total replicas) and the view-change protocol.

For example let's say you want to set the total number of replicas to 10, with 5 failures:

```Bash
cargo r -- fail-test -n 10 -f 5
```

### Configuration discovery test

The subcommand `dis-test` can test the approximate time required for configuration discovery. Note that only in the current test mode will the console print partial output relating to configuration discovery.

Please lookup the document of `dis-test` before using it.

```Bash
cargo r -- dis-test -h
```

For example let's say you want 2 replicas to start configuration discovery at the same time 15s after consensus starts with a total of 10 replicas, and simulate an environment with frequent membership requests.

```Bash
cargo r -- dis-test -n 10 -d 2 -w 15000 -b
```

## Runs via configuration generation (supports multiple hosts)

### Runs on localhost (For optimal performance, use release mode).

```Bash
cargo build --release
```
Find hydra under target/release, run
```Bash
./hydra -h
```
as well as
```Bash
./hydra config-gen --help
```
to view parameter definitions.

The subcommand `config-gen` provide a way to generate multiple files for multi replicas over multi hosts.
It also helps to generate a bunch of bash scripts to distribute files in accordance, run all the nodes, and
collect the results.

Please lookup the document of config-gen before using it.

**Remember that, default `config-gen` will run in dry-run mode, in which all the files will be print to the console.
By specify `-w` you can flush these files to disks.**

Let's say we want 10 replicas to reach consensus on localhost, with 7 replicas in the initial configuration and 3 replicas to leave later. Replicas who initiate membership requests run in hybrid mode (the joining replica will leave again 15s after joining, ditto for the leaving replica). At least two replicas send a join request and a leave request at the same time.

Create a new localhost folder in the parent directory and generate relevant configuration files (injection rate: 5000, batch size: 250, transaction size: 128, timeout: 5000ms):

```Bash
./hydra -r 5000 -b 250 -t 128 --timeout 5000 config-gen -n 10 -i 7 -l 3 -m  -e ../ -w localhost
```

 Then copy hydra to the localhost directory and run 
 ```Bash
 bash run.sh 
```

Of course, you can also manually modify the parameters in the configuration file to make secondary adjustments before running, for example, say manually adjusting the time when each replica initiates a membership request for the first time. 

(View more specific logs, by adding 'RUST_LOG=TRACE' to the process)

### Multi-host Config Generation

Let's say we want to distribute 10 replicas over 2 hosts (IP_OF_SERVER_1, IP_OF_SERVER_2) with the above parameters.

```Bash
./hydra -r 5000 -b 250 -t 128 --timeout 5000 config-gen -n 10 -i 7 -l 3 -m IP_OF_SERVER_1 IP_OF_SERVER_2 --export-dir configs -w
```

Now, some files are exported in `./configs`.

Then, distribute these files to corresponding servers.

**Please make sure you have right to login servers via `ssh IP_OF_SERVER`.**

```
cd ./configs

bash run-all.sh
```

This script will distribute configs, run replicas, and collect experiment results into your local directory.


### How is the test work flow?

First, we can try to export a basic config file. (This can be optional)
And you can edit further `base_config.json` if you like.

```
cargo r -- --export-path base_config.json
```

Next, You will use `config-gen` to generate all the files for a committee in a single tests.

```
cargo r -- --config base_config.json config-gen --number <NUMBER> --initial-number <INITIAL_NUMBER> IPs_OF_SERVER --export-dir configs -w
```

If you skip the first step, then just run (default config will be used):

```
cargo r -- config-gen --number <NUMBER> --initial-number <INITIAL_NUMBER> IPs_OF_SERVER --export-dir configs -w
```

As the section above, run:

```
cd configs/
bash run-all.sh
```

Then you'll get the results.

### How performance is calculated in this work?

In our implmentation, there are three timestamps for a single transaction.

1. T1: A timestamp when transaction is created.
2. T2: A timestamp when block is packed by consensus node.
3. T3: A timestamp when it's finalized in a block.

End-to-end performance is calculated via T1 and T3, and 
Consensus performance is calculated via T2 and T3.