use shloss::init_logging;
use tracing::info;

fn main() -> anyhow::Result<()> {
    info!("shloss: begin startup");
    init_logging();

    info!("shloss: ready");
    Ok(())
}
