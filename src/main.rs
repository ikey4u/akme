mod error;

use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::{Read, Write},
    path,
    sync::{Arc, Mutex},
    time::Duration,
};

use acme2::{
    gen_rsa_private_key, AccountBuilder, AuthorizationStatus, ChallengeStatus,
    Csr, DirectoryBuilder, OrderBuilder, OrderStatus,
};
use anyhow::{bail, ensure, Context};
use axum::{extract::Path, routing::get, Router};
use chrono::Local;
use clap::{Parser, Subcommand};
use error::AxumResult;
use once_cell::sync::Lazy;
use tokio::{sync::oneshot::Sender, time::sleep};
use x509_parser::pem::parse_x509_pem;

use crate::error::Result;

static CHALLENGES: Lazy<Arc<Mutex<HashMap<String, String>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub struct CertManager {
    // `Sender` cannot be moved out in `Drop`, here we use Option trick to finish that
    stop: Option<Sender<()>>,
    domain: String,
    emails: Vec<String>,
    acmedir: String,
}

impl CertManager {
    pub async fn new<A: AsRef<str>, B: AsRef<str>>(
        domain: A,
        emails: Vec<String>,
        acmedir: B,
    ) -> Result<Self> {
        // Start challenge solve server
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 80))
            .await
            .context("cannot listen to port 80")?;
        tokio::spawn(async {
            // HTTP-01 challenge will access URL `http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>`,
            // see https://letsencrypt.org/docs/challenge-types/
            let app = Router::new()
                .route(
                    "/.well-known/acme-challenge/:token",
                    get(Self::solve_acme_challenge),
                )
                .route("/", get(|| async {}));
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
            {
                log::error!("challenge solve server exits with error: {e}");
            } else {
                log::info!("challenge solve server exits successfully");
            }
        });

        log::info!("wait challenge solve server to start ..");
        let timeout = 5;
        let wait_start_at = Local::now().timestamp();
        loop {
            sleep(Duration::from_millis(300)).await;
            if reqwest::get("http://127.0.0.1:80").await.is_ok() {
                break;
            }
            if Local::now().timestamp() - wait_start_at > timeout {
                bail!("challenge solve server does not start in {timeout} seconds");
            }
        }
        log::info!("challenge solve server started");

        Ok(Self {
            stop: Some(tx),
            domain: domain.as_ref().to_owned(),
            emails,
            acmedir: acmedir.as_ref().to_owned(),
        })
    }

    /// Issue or renew an HTTPS certificate pair `(certificate, private_key)`
    pub async fn issue(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (dir, domain) = if cfg!(feature = "dev-issue") {
            let acme_root_ca = env::var("ACME_ROOT_CA")?;
            let certbuf = tokio::fs::read(acme_root_ca).await?;
            let cert = reqwest::Certificate::from_pem(&certbuf)?;
            let client = reqwest::Client::builder()
                .add_root_certificate(cert)
                .build()?;
            (
                DirectoryBuilder::new(self.acmedir.clone())
                    .http_client(client)
                    .build()
                    .await?,
                "example.com",
            )
        } else {
            (
                DirectoryBuilder::new(self.acmedir.clone()).build().await?,
                self.domain.as_str(),
            )
        };
        let account = AccountBuilder::new(dir.clone())
            .contact(self.emails.clone())
            .terms_of_service_agreed(true)
            .build()
            .await?;
        let order = OrderBuilder::new(account)
            .add_dns_identifier(domain.to_owned())
            .build()
            .await?;

        let mut authed = false;
        let authorizations = order.authorizations().await?;
        for auth in authorizations {
            let challenge = auth.get_challenge("http-01").unwrap();
            let token = challenge
                .token
                .as_deref()
                .context("challenge contains no token")?;
            let secret = challenge.key_authorization()?;
            let secret = secret.context("challenge token has no value")?;
            {
                let mut chals = CHALLENGES.lock().unwrap();
                chals.insert(token.to_owned(), secret.to_owned());
            }

            let challenge = challenge.validate().await?;
            let challenge =
                challenge.wait_done(Duration::from_secs(5), 3).await?;
            if challenge.status != ChallengeStatus::Valid {
                continue;
            }

            let authorization =
                auth.wait_done(Duration::from_secs(5), 3).await?;
            if authorization.status != AuthorizationStatus::Valid {
                continue;
            }

            authed = true;
        }
        if !authed {
            bail!("failed to finish challenge or authorization");
        }

        let order = order.wait_ready(Duration::from_secs(5), 3).await?;
        ensure!(
            order.status == OrderStatus::Ready,
            "timeout when wait certificate order ready"
        );

        let pkey = gen_rsa_private_key(4096)?;
        let order = order.finalize(Csr::Automatic(pkey.clone())).await?;
        let order = order.wait_done(Duration::from_secs(5), 3).await?;
        ensure!(
            order.status == OrderStatus::Valid,
            "timeout when wait certificate generation"
        );
        let certs = order.certificate().await?.unwrap();
        ensure!(certs.len() > 1, "unexpected empty certificate");

        let pkey_pem_bytes = pkey.private_key_to_pem_pkcs8().expect("to_pem");
        let key = String::from_utf8_lossy(&pkey_pem_bytes);
        let cert = certs[0]
            .to_pem()
            .context("cannot convert certificate to PEM format")?;
        Ok((cert, key.as_bytes().to_vec()))
    }

    async fn solve_acme_challenge(
        Path(token): Path<String>,
    ) -> AxumResult<String> {
        // Token contains only base64url allowed characters, see
        // https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.8.3
        for ch in token.chars() {
            if ('0'..='9')
                .chain('a'..='z')
                .chain('A'..='Z')
                .chain(['-', '_'])
                .any(|x| x == ch)
            {
                continue;
            }
            axum_bail!(
                "acme challenge token {token} contains invalid characters"
            );
        }

        let chals = CHALLENGES.lock().unwrap();
        let secret = chals
            .get(&token)
            .context(format!("no required secret found for token {token}"))?;
        Ok(secret.to_owned())
    }
}

impl Drop for CertManager {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            log::info!("Send stop signal to challenge server");
            _ = stop.send(());
        }
    }
}

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

pub async fn akme_start<D: AsRef<str>, P: AsRef<path::Path>, S: AsRef<str>>(
    domain: D,
    emails: Vec<String>,
    acmedir: S,
    ssldir: P,
) -> Result<()> {
    let (domain, ssldir) = (domain.as_ref(), ssldir.as_ref());

    let mgr = CertManager::new(&domain, emails, acmedir.as_ref()).await?;
    let certpath = ssldir.join(format!("{}.crt", domain));
    let mut has_idle_message = false;
    loop {
        let is_expired = if certpath.exists() {
            let mut f = File::open(&certpath)?;
            let mut buf = vec![];
            f.read_to_end(&mut buf)?;
            let (_, cert) = parse_x509_pem(&buf)?;
            let cert = cert.parse_x509()?;
            if let Some(t) = cert.validity().time_to_expiration() {
                t.whole_hours() < 6
            } else {
                true
            }
        } else {
            true
        };

        if !is_expired {
            if cfg!(feature = "dev-issue") {
                panic!("remove your existed test certificate and test again");
            }
            if !has_idle_message {
                log::info!("Certificate is valid, and I will go to sleep ...");
                has_idle_message = true;
            }
            sleep(Duration::from_millis(300)).await;
            continue;
        }

        let skpath = ssldir.join(format!("{}.key", domain));
        let (cert, sk) = mgr.issue().await?;
        let mut f = File::create(&certpath)?;
        f.write_all(cert.as_slice())?;
        let mut f = File::create(&skpath)?;
        f.write_all(sk.as_slice())?;

        has_idle_message = false;
        log::info!(
            "Certificate and key are updated, certificate: {}; key: {}",
            certpath.display(),
            skpath.display()
        );

        if cfg!(feature = "dev-issue") {
            _ = tokio::fs::remove_file(certpath).await;
            _ = tokio::fs::remove_file(skpath).await;
            break;
        }
    }

    Ok(())
}

pub fn init_tracing<P: AsRef<path::Path>, S: AsRef<str>>(
    logdir: P,
    prefix: S,
) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::{
        filter::LevelFilter,
        fmt::time::ChronoLocal,
        layer::{Layer, SubscriberExt},
        util::SubscriberInitExt,
    };

    let logdir = logdir.as_ref();
    let prefix = prefix.as_ref();
    let file_appender = tracing_appender::rolling::daily(logdir, prefix);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let layers = vec![
        tracing_subscriber::fmt::layer()
            .with_writer(file_writer)
            .with_ansi(false)
            .with_timer(ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.6f".to_owned()))
            .with_filter(LevelFilter::DEBUG)
            .boxed(),
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_timer(ChronoLocal::new("%Y-%m-%dT%H:%M:%S.%.6f".to_owned()))
            .with_filter(LevelFilter::INFO)
            .boxed(),
    ];
    tracing_subscriber::registry().with(layers).init();
    log::debug!("Tracing initialized");
    guard
}

pub async fn app() -> Result<()> {
    let cli = Cli::parse();

    let logdir = path::Path::new("log/akme");
    if !logdir.exists() {
        fs::create_dir_all(logdir).expect("failed to create log directory");
    }
    let _guard = init_tracing(logdir, "akme");

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
            akme_start(domain, emails, acmedir, ssldir).await?
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
    let domain = "example.com".to_owned();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let rsp = domain.clone();
    let port = (1024..=65535)
        .find(|x| std::net::TcpListener::bind(("127.0.0.1", *x)).is_ok())
        .unwarp();
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

#[tokio::test]
#[cfg(feature = "dev-issue")]
async fn dev_issue() {
    let _guard = init_tracing("target", "akme");
    akme_start(
        "exapmle.com".to_owned(),
        vec!["admin@example.com".to_owned()],
        env::var("ACME_DIR_URL").unwrap().to_owned(),
        env::current_dir().unwrap(),
    )
    .await
    .unwrap()
}
