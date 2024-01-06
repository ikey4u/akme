use std::path;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[macro_export]
macro_rules! axum_bail {
    ($msg:literal $(,)?) => {
        return Err(anyhow::anyhow!($msg).into())
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(anyhow::anyhow!($fmt, $($arg)*).into())
    };
}

pub type Result<T> = anyhow::Result<T>;

pub type AxumResult<T> = anyhow::Result<T, AxumError>;

pub struct AxumError(anyhow::Error);

impl IntoResponse for AxumError {
    fn into_response(self) -> Response {
        log::error!("axum server error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Oops! something went wrong".to_owned(),
        )
            .into_response()
    }
}

impl<E> From<E> for AxumError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
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
