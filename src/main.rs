mod acme;
mod error;

use std::{
    env,
    fs::{self},
    path,
};

use anyhow::ensure;
use clap::{Parser, Subcommand};

use crate::error::Result;

/// akme - HTTPS certificate made easy
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start akme server
    Start {
        /// Your website domain such as `example.com` without any prefix like https or http
        #[arg(long)]
        domain: String,
        /// Emails of your domain onwers
        #[arg(long)]
        email: Option<Vec<String>>,
        /// ACME directory url, default to the one letsencrypt provides
        #[arg(long)]
        acmedir: Option<String>,
        /// An existed directory (both `.` and `..` are accepted) where you want
        /// to store the generated files in which named `<domain>.crt` and
        /// `<domain>.key`, respectively
        #[arg(long, verbatim_doc_comment)]
        ssldir: Option<path::PathBuf>,
        /// Command to reload your web server
        #[arg(long, short = 'c')]
        reload: Option<String>,
    },
    /// Stop akme server
    Stop,
    /// View akme log
    Log,
}

pub async fn app() -> Result<()> {
    let cli = Cli::parse();

    let logdir = path::Path::new("log/akme");
    if !logdir.exists() {
        fs::create_dir_all(logdir).expect("failed to create log directory");
    }
    let _guard = error::init_tracing(logdir, "akme");

    match &cli.command {
        Some(Command::Start {
            domain,
            email,
            acmedir,
            ssldir,
            reload,
        }) => {
            let ssldir = if let Some(ssldir) = ssldir.as_ref() {
                ssldir.to_owned()
            } else {
                env::current_dir()?
            };

            let emails = if let Some(email) = email {
                email.to_owned()
            } else {
                vec![]
            };

            let acmedir = if let Some(acmedir) = acmedir {
                acmedir.as_str()
            } else {
                "https://acme-v02.api.letsencrypt.org/directory"
            };

            ensure!(
                ssldir.exists(),
                "ssldir {} does not exist",
                ssldir.display()
            );
            let ssldir = ssldir.canonicalize()?;
            acme::start(domain, emails, acmedir, ssldir).await?
        }
        _ => todo!(),
    }

    Ok(())
}

#[tokio::main]
pub async fn main() {
    if let Err(e) = app().await {
        println!("application exits with error: {e:?}");
        std::process::exit(1);
    }
}

#[tokio::test]
#[cfg(feature = "dev-check-hosts")]
async fn dev_check_hosts() {
    use std::time::Duration;

    use axum::{routing::get, Router};

    let domain = "example.com".to_owned();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let rsp = domain.clone();
    let port = (1024..=65535)
        .find(|x| std::net::TcpListener::bind(("127.0.0.1", *x)).is_ok())
        .unwrap();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        let app = Router::new().route("/", get(|| async { rsp }));
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .unwrap();
    });

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(300))
        .build()
        .unwrap();
    let rsp = client
        .get(format!("http://{domain}:{port}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    _ = tx.send(());

    assert_eq!(domain, rsp);
}
