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
