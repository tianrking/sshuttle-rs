use anyhow::Result;

use crate::config::WinNativeWorkerArgs;

pub async fn run(args: WinNativeWorkerArgs) -> Result<()> {
    println!(
        "[win-native-worker] started: listen_port={} proxy={} bypass_processes={} ",
        args.listen_port,
        args.proxy_addr,
        args.bypass_processes.join(",")
    );
    println!("[win-native-worker] minimal native backend active; packet divert engine will be extended in next milestone");

    tokio::signal::ctrl_c().await?;
    println!("[win-native-worker] stop signal received, exiting");
    Ok(())
}