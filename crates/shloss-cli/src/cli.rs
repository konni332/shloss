use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "shloss-cli", about = "Shloss admin CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate a new client_credentials.toml with a first service key
    GenerateConfig {
        /// Name of the first service
        #[arg(short, long)]
        name: String,
    },
    /// Generate a new service key and append it to client_credentials.toml
    GenerateKey {
        /// Name of the service this key belongs to
        #[arg(short, long)]
        name: String,
    },
}
