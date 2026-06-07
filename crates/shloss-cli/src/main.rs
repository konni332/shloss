use std::path::Path;

use anyhow::{Context, bail};
use clap::Parser;
use dialoguer::Confirm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cli::{Cli, Command};

mod cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenerateConfig { name } => {
            let key = generate_service_key()?;
            let hash = hash_key(&key);
            let vault_id = Uuid::new_v4();
            generate_config(&name, &hash, vault_id)?;
            print_raw_key(&name, &key);
        }
        Command::GenerateKey { name } => {
            let key = generate_service_key()?;
            let hash = hash_key(&key);
            let vault_id = Uuid::new_v4();
            append_new_key(&name, &hash, vault_id)?;
            print_raw_key(&name, &key);
        }
        Command::RotateKey { name } => {
            let new_key = generate_service_key()?;
            let hash = hash_key(&new_key);
            let mut config = ClientConfig::load()?;
            let key = config
                .keys
                .iter_mut()
                .find(|k| k.name == name)
                .context(format!("No service by the name '{name}' found. Try `shloss-cli generate_key to add a new service key`"))?;
            key.hash = hash;
            write_config(&config, Path::new("./client_credentials.toml"))?;
            print_raw_key(&name, &new_key);
        }
    };
    Ok(())
}

fn generate_config(name: &str, hash: &str, vault_id: Uuid) -> anyhow::Result<()> {
    let path = Path::new("./client_credentials.toml");
    if path.exists() {
        let overwrite = Confirm::new()
            .with_prompt("client_credentials.toml already exists. Do you want to overwrite it?")
            .default(false)
            .interact()?;
        if !overwrite {
            bail!("aborted");
        }
    }
    let config = ClientConfig {
        keys: vec![ServiceKey {
            name: name.to_string(),
            hash: hash.to_string(),
            vault_id,
        }],
    };
    write_config(&config, path)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientConfig {
    keys: Vec<ServiceKey>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceKey {
    name: String,
    hash: String,
    vault_id: Uuid,
}

impl ClientConfig {
    fn load() -> anyhow::Result<Self> {
        let path = Path::new("./client_credentials.toml");
        let toml_str = std::fs::read_to_string(path)?;
        let toml: Self = toml::from_str(&toml_str)?;
        Ok(toml)
    }
}

fn append_new_key(name: &str, hash: &str, vault_id: Uuid) -> anyhow::Result<()> {
    let path = Path::new("./client_credentials.toml");
    if !path.exists() {
        bail!("no client_credentials.toml found, run generate-config first");
    }
    let mut config: ClientConfig = toml::from_str(&std::fs::read_to_string(path)?)?;
    if config.keys.iter().any(|k| k.hash == hash) {
        bail!("Key collision, try again");
    }
    for key in config.keys.iter_mut() {
        if key.name == name {
            let prompt = format!("Key for '{name}' already exsits. Do you want to overwrite it?");
            let overwrite = Confirm::new()
                .with_prompt(&prompt)
                .default(false)
                .interact()?;
            if !overwrite {
                bail!("aborted");
            } else {
                key.hash = hash.to_string();
                return write_config(&config, path);
            }
        }
    }
    config.keys.push(ServiceKey {
        name: name.to_string(),
        hash: hash.to_string(),
        vault_id,
    });
    write_config(&config, path)
}

fn write_config(cfg: &ClientConfig, path: &Path) -> anyhow::Result<()> {
    let toml_str = toml::to_string_pretty(cfg)?;
    std::fs::write(path, toml_str)?;
    Ok(())
}

fn generate_service_key() -> anyhow::Result<String> {
    let secret = generate_secret()?;
    let full_key = format!("shloss_{}", secret);
    Ok(full_key)
}

fn hash_key(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw);
    hex::encode(hasher.finalize())
}

fn generate_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn print_raw_key(name: &str, raw: &str) {
    println!();
    println!("Generated service key for '{}'", name);
    println!("--------------------------------------------------");
    println!("{}", raw);
    println!("--------------------------------------------------");
    println!("This key will not be shown again. Store it safely!");
    println!();
}
