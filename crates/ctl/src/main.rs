use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = std::io::stdout().lock();
    match ainkrad_ctl::cmd::run(&args, &mut out).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ainkradctl: {e}");
            ExitCode::from(e.code())
        }
    }
}
