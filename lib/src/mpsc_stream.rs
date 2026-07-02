// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use futures_util::FutureExt;
use futures_util::Stream;
use futures_util::StreamExt;
use futures_util::stream;
use slog::Logger;
use slog::error;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::SendError;
use tokio::task::JoinError;

pub(crate) fn mpsc_stream<T, E, F>(
    log: Option<Logger>,
    f: F,
) -> impl Stream<Item = Result<T, E>> + 'static
where
    T: Send + 'static,
    E: std::error::Error + From<JoinError> + Send + 'static,
    F: FnOnce(Sender<Result<T, E>>) -> Result<(), SendError<Result<T, E>>>
        + Send
        + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::task::spawn_blocking(move || f(tx));
    stream::poll_fn(move |cx| rx.poll_recv(cx)).chain(
        async move {
            stream::iter(match task.await {
                Ok(Ok(())) => None,

                // It is presumed a `SendError` is returned from an attempt to
                // send a value across the channel created by `mpsc_stream`.
                // This would indicate that either the receiver was explicitly
                // closed (which this function does not do), or that the
                // receiver was dropped (which would not be possible if we are
                // in this match statement). Nonetheless, we will log such an
                // oddity, and if the value that failed to send itself contained
                // an error, we will return it as this stream's final value.
                Ok(Err(SendError(Ok(_)))) => {
                    log.inspect(|log| {
                        error!(log, "stream reader unexpectedly hung up");
                    });
                    None
                }
                Ok(Err(SendError(Err(error)))) => {
                    log.inspect(|log| {
                        error!(
                            log,
                            "stream reader unexpectedly hung up \
                            before receiving error";
                            "err" => &crate::util::error_chain(&error),
                        );
                    });
                    Some(Err(error))
                }

                Err(join_error) => Some(Err(E::from(join_error))),
            })
        }
        .flatten_stream(),
    )
}
