use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "Hydra")]
#[command(author = "Xuyang Liu <liuxuyangcs@gmail.com>")]
#[command(about = "Hydra", version)]
pub(crate) struct Cli {
    /// Path to the config file
    #[arg(short, long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Set ID of current node.
    #[arg(short, long, default_value_t = 0)]
    pub(crate) id: u64,

    /// Addresses of known nodes.
    #[arg(short, long, default_value_t = String::from("localhost:8123"))]
    addr: String,


    /// Set injection_rate, default value is 100_000 (tx/s).
    #[arg(short, long)]
    pub(crate) rate: Option<u64>,

    /// Set transaction_size, default value is 256 (Bytes).
    #[arg(short, long)]
    pub(crate) transaction_size: Option<usize>,

    /// Set batch_size, default value is 100 (tx/block).
    #[arg(short, long)]
    pub(crate) batch_size: Option<usize>,

    /// Pretend to be a failure nodes.
    #[arg(long)]
    pub(crate) pretend_failure: bool,

    /// Disable metrics.
    #[arg(long)]
    pub(crate) disable_metrics: bool,

    /// Rotate leadership every `rotate_every` key blocks.
    #[arg(long)]
    pub(crate) leader_rotation: Option<usize>,

    /// Maximum number of transactions in the mempool.
    #[arg(long)]
    pub(crate) mempool_size: Option<usize>,

    /// Pacemaker timeout.
    #[arg(long)]
    pub(crate) timeout: Option<usize>,

    /// Export metrics to file when node exits.
    #[arg(short, long)]
    pub(crate) export_path: Option<PathBuf>,

    /// Subcommands
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Parser, Debug)]
pub(crate) enum Commands {
    /// Run the node within memory network.
    /// Member join test: 'initial_number' replicas forming the initial configuration.  
    /// The remaining replicas will send join requests to join later.
    /// Please keep the |L|<=initial_number<=number
    MemoryTestJoin {
        /// Number of nodes (universe).
        #[arg(short, long, default_value_t = 4)]
        number: usize,

        /// Number of nodes (M0).
        #[arg(short, long, default_value_t = 4)]
        initial_number: usize,

        /// Sequential join (replicas not in the initial configuration send join requests at 5s intervals one-by-one).
        /// Set to false to have replicas send join requests at the same time.
        #[arg(short, long, default_value_t = false)]
        sequential_join: bool,
    },
    /// Run the node within memory network.
    /// Member leave test: 'number' replicas forming the initial configuration.  
    /// 'leave_number' replicas will leave later by sending leave requests.
    /// Please keep the number-leave_number>=|L|
    MemoryTestLeave {
      /// Number of nodes (universe, also M0).
      #[arg(short, long, default_value_t = 4)]
      number: usize,

      /// Number of the leaving nodes
      #[arg(short, long, default_value_t = 0)]
      leave_number: usize,

      /// Sequential leave ('leave_number' replicas send leave requests at 5s intervals one-by-one).
      /// Set to false to have replicas send leave requests at the same time.
      #[arg(short, long, default_value_t = false)]
      sequential_leave: bool,
    },
    /// Run the node within memory network.
    /// 'initial_number' replicas forming the initial configuration.
    /// The remaining replicas will send join requests to join later，and then leave again 15s after joining.
    /// 'leave_number' replicas will leave later by sending leave requests，and then join again 15s after leaving.
    /// Please keep |L|<=initial_number<=number and initial_number-leave_number>=|L|
    MemoryTestHybrid {
      /// Number of nodes (universe).
      #[arg(short, long, default_value_t = 4)]
      number: usize,

      /// Number of nodes (M0).
      #[arg(short, long, default_value_t = 4)]
      initial_number: usize,

      /// Number of the leaving nodes
      #[arg(short, long, default_value_t = 0)]
      leave_number: usize,

      /// Sequential (replicas send membership requests at 5s intervals one-by-one).
      /// Set to false to have at least two replicas send a join request and a leave request at the same time.
      #[arg(short, long, default_value_t = false)]
      sequential: bool,
    },
    /// Run the node in memory network with some nodes are failure.
    FailTest {
        /// Number of failures.
        #[arg(short, long, default_value_t = 1)]
        number: usize,
    },

    /// Generate all configs for a single test.
    ///
    /// This command distributes `number` replicas into `hosts`,
    /// automatically assign id and addr.
    ConfigGen {
        /// Number of nodes (universe).
        #[arg(short, long, default_value_t = 4)]
        number: usize,

        /// Number of nodes (M0).
        #[arg(short, long, default_value_t = 4)]
        initial_number: usize,

        /// hosts to distribute replicas.
        hosts: Vec<String>,

        /// Path to export configs.
        #[arg(short, long, value_name = "DIR")]
        export_dir: Option<PathBuf>,

        /// automatically export configs to a new directory.
        #[arg(short, long)]
        auto_naming: bool,

        /// Write all the configs and scripts to file.
        #[arg(short, long)]
        write_file: bool,

        /// Number of failure nodes
        ///
        /// This value must follow the rule of BFT,
        /// that 3f+1 <= n.
        #[arg(short, long, default_value_t = 0)]
        failure_nodes: usize,
    },
}
