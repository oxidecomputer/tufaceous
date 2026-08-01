// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use camino::Utf8PathBuf;
use iddqd::IdOrdItem;
use iddqd::IdOrdMap;
use iddqd::id_upcast;
use rawzip::ReaderAt;
use rawzip::ZipArchive;
use reqwest::Client;
use reqwest::Response;
use reqwest::StatusCode;
use reqwest::header::ACCEPT_RANGES;
use reqwest::header::CONTENT_LENGTH;
use reqwest::header::CONTENT_RANGE;
use reqwest::header::HeaderValue;
use reqwest::header::RANGE;
use slog::Logger;
use slog::debug;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use url::Url;

use crate::ZipTransport;
use crate::error::DebugByteString;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;
use crate::zip_transport::EOCD_MAX_SEARCH_SPACE;

static CLIENT: LazyLock<Client> = LazyLock::new(Client::new);
const LOCAL_HEADER_SIZE: usize = 30;

impl ZipTransport<HttpRangeReader> {
    pub async fn from_http_file(url: Url, log: &Logger) -> Result<Self, Error> {
        let archive_path = Utf8PathBuf::from(url.to_string());
        let reader = try_path!(
            HttpRangeReader::new(url, log).await,
            OpenFile,
            archive_path
        );
        let log = log.clone();
        tokio::task::spawn_blocking(move || {
            let end_offset = reader.length;
            let mut buffer = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
            let archive = try_archive_path!(
                ZipArchive::with_max_search_space(EOCD_MAX_SEARCH_SPACE)
                    .locate_in_reader(reader, &mut buffer, end_offset)
                    .map_err(|(_, error)| error),
                ReadZipEocd,
                archive_path
            );
            Self::from_impl_blocking(
                archive,
                Some(archive_path),
                Some(buffer),
                &log,
            )
        })
        .await?
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct HttpRangeReader {
    url: Url,
    log: Logger,
    length: u64,
    local_header_cache: Mutex<BTreeMap<u64, Option<[u8; LOCAL_HEADER_SIZE]>>>,
    ranges: Mutex<IdOrdMap<RangeManager>>,
}

impl HttpRangeReader {
    pub(super) async fn new(
        url: Url,
        log: &Logger,
    ) -> Result<Self, std::io::Error> {
        let response = CLIENT
            .head(url.clone())
            .send()
            .await
            .map_err(RangeError::Reqwest)?;
        let length = if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            // HEAD not allowed... try sending a GET request for a single byte,
            // and determining the file size from the content-range header.
            let response = CLIENT
                .get(url.clone())
                .header(RANGE, "bytes=0-0")
                .send()
                .await
                .and_then(Response::error_for_status)
                .map_err(RangeError::Reqwest)?;
            if response.status() != StatusCode::PARTIAL_CONTENT
                && response.status() != StatusCode::RANGE_NOT_SATISFIABLE
            {
                return Err(RangeError::Unsupported.into());
            }
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .ok_or(RangeError::NoContentRange)?;
            content_length_from_content_range(content_range)?
        } else {
            // Other error statuses should not proceed.
            let response =
                response.error_for_status().map_err(RangeError::Reqwest)?;
            // `accept-ranges: bytes` must be present.
            if response
                .headers()
                .get(ACCEPT_RANGES)
                .filter(|v| v.as_bytes() == b"bytes")
                .is_none()
            {
                return Err(RangeError::Unsupported.into());
            }
            // Retrieve the file length from the content-length header.
            let Some(content_length) = response.headers().get(CONTENT_LENGTH)
            else {
                return Err(RangeError::NoContentLength.into());
            };
            content_length
                .to_str()
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    RangeError::InvalidContentLength(
                        content_length.as_bytes().to_vec(),
                    )
                })?
        };
        Ok(Self {
            url,
            log: log.clone(),
            length,
            local_header_cache: Mutex::new(BTreeMap::new()),
            ranges: Mutex::new(IdOrdMap::new()),
        })
    }

    pub(super) fn hint_local_header(&mut self, offset: u64, path_len: u64) {
        self.local_header_cache.get_mut().unwrap().insert(offset, None);
        insert_range(
            self.ranges.get_mut().unwrap(),
            offset..(offset + path_len + usize64!(LOCAL_HEADER_SIZE)),
        );
    }

    pub(super) fn hint_range(&self, range: Range<u64>) {
        insert_range(&mut self.ranges.lock().unwrap(), range);
    }
}

fn insert_range(ranges: &mut IdOrdMap<RangeManager>, range: Range<u64>) {
    let mut entry = ranges
        .entry(range.start)
        .or_insert_with(|| RangeManager::new(range.clone()));
    if entry.range.end > range.end {
        entry.range.end = range.end;
    }
}

impl ReaderAt for HttpRangeReader {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        if buf.len() == LOCAL_HEADER_SIZE
            && let Some(Some(cached)) =
                self.local_header_cache.lock().unwrap().get(&offset)
        {
            buf.copy_from_slice(cached);
            return Ok(LOCAL_HEADER_SIZE);
        }

        if offset >= self.length {
            return Ok(0);
        }
        let range = offset..(offset + usize64!(buf.len())).min(self.length);
        if range.is_empty() {
            return Ok(0);
        }

        // Check if we already know about a range starting at `offset`.
        let mut manager = self
            .ranges
            .lock()
            .unwrap()
            .remove(&offset)
            // If not, make one up for the range we're being asked to read.
            .unwrap_or_else(|| RangeManager::new(range.clone()));

        let url = self.url.clone();
        let log = self.log.clone();
        let max_len = buf.len();
        // If `next_chunk` fails we drop the manager.
        let (manager, chunk) = Handle::current().block_on(async move {
            let chunk = manager.next_chunk(url, &log, max_len).await?;
            Ok::<_, RangeError>((manager, chunk))
        })?;
        let Some(chunk) = chunk else {
            return Ok(0);
        };

        // Put the manager back in the map.
        if !manager.range.is_empty() {
            self.ranges.lock().unwrap().insert_overwrite(manager);
        }

        if chunk.len() == LOCAL_HEADER_SIZE
            && let Some(cache_entry) =
                self.local_header_cache.lock().unwrap().get_mut(&offset)
        {
            let mut cached = [0; 30];
            cached.copy_from_slice(&chunk);
            *cache_entry = Some(cached);
        }

        buf[..chunk.len()].copy_from_slice(&chunk);
        Ok(chunk.len())
    }
}

#[derive(Debug)]
struct RangeManager {
    range: Range<u64>,
    response: ExpiringResponse,
    buf: Bytes,
}

impl RangeManager {
    fn new(range: Range<u64>) -> Self {
        Self { range, response: ExpiringResponse::new(), buf: Bytes::new() }
    }

    async fn next_chunk(
        &mut self,
        url: Url,
        log: &Logger,
        max_len: usize,
    ) -> Result<Option<Bytes>, RangeError> {
        // If we have bytes left over from a previous call, return those.
        if !self.buf.is_empty() {
            let chunk = self.buf.split_to(self.buf.len().min(max_len));
            self.range.start += usize64!(chunk.len());
            return Ok(Some(chunk));
        }

        let mut response = if let Some(response) = self.response.take().await {
            response
        } else {
            let range =
                format!("bytes={}-{}", self.range.start, self.range.end - 1);
            debug!(
                log,
                "sending request for range";
                "range" => &range,
                "url" => url.as_str(),
            );
            let response = CLIENT
                .get(url)
                .header(RANGE, range)
                .send()
                .await
                .map_err(RangeError::Reqwest)?;
            if response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
                return Ok(None);
            }
            let response =
                response.error_for_status().map_err(RangeError::Reqwest)?;
            if response.status() != StatusCode::PARTIAL_CONTENT {
                return Err(RangeError::NoContentRange);
            }
            response
        };

        if let Some(mut chunk) =
            response.chunk().await.map_err(RangeError::Reqwest)?
            && !chunk.is_empty()
        {
            self.buf = chunk.split_off(chunk.len().min(max_len));
            self.range.start += usize64!(chunk.len());
            // If there's more range to read, save the response for later.
            if !self.range.is_empty() {
                self.response.insert(response);
            }
            Ok(Some(chunk))
        } else {
            Ok(None)
        }
    }
}

impl IdOrdItem for RangeManager {
    type Key<'a> = u64;

    fn key(&self) -> Self::Key<'_> {
        self.range.start
    }

    id_upcast!();
}

/// Possibly holds a `Response`, but drops it after 15 seconds.
///
/// We do this to avoid holding responses idle for too long without using them,
/// then potentially coming back later and finding out the server has rightfully
/// hung up and returning a spurious error.
#[derive(Debug)]
struct ExpiringResponse {
    tx: Option<oneshot::Sender<oneshot::Sender<Response>>>,
}

impl ExpiringResponse {
    // You know that saying about timeouts?
    //
    // This number is guided by the belief that the point of holding open a
    // response is because we're doing sequential reads. In general we don't
    // think it should take more than 15 seconds to deal with a particular
    // response chunk, and that 60 seconds appears to be a usual timeout for
    // remote proxies (the specific consideration here is Buildomat, which is
    // frontend by NGINX, which defaults to a 60-second timeout).
    const EXPIRATION: Duration = Duration::from_secs(15);

    fn new() -> Self {
        Self { tx: None }
    }

    fn insert(&mut self, response: Response) {
        let (tx, rx) = oneshot::channel();
        self.tx = Some(tx);
        tokio::task::spawn(async move {
            // An underlying error means the sender was dropped or the timeout
            // elapsed; either of which means we simply drop `response`.
            if let Ok(Ok(tx)) = tokio::time::timeout(Self::EXPIRATION, rx).await
            {
                // If the other end hung up, oh well.
                tx.send(response).ok();
            }
        });
    }

    async fn take(&mut self) -> Option<Response> {
        let (tx, rx) = oneshot::channel();
        self.tx.take()?.send(tx).ok();
        rx.await.ok()
    }
}

#[derive(Debug, thiserror::Error)]
enum RangeError {
    #[error(transparent)]
    Reqwest(reqwest::Error),
    #[error("range requests not supported")]
    Unsupported,
    #[error("unknown content length")]
    NoContentLength,
    #[error("content-length header {:?} invalid", DebugByteString(.0))]
    InvalidContentLength(Vec<u8>),
    #[error("content-range header not found")]
    NoContentRange,
    #[error("content-range header {:?} invalid", DebugByteString(.0))]
    InvalidContentRange(Vec<u8>),
}

impl From<RangeError> for std::io::Error {
    fn from(error: RangeError) -> Self {
        use std::io::ErrorKind;

        std::io::Error::new(
            match &error {
                RangeError::Reqwest(_) => ErrorKind::Other,
                RangeError::Unsupported => ErrorKind::Unsupported,
                RangeError::NoContentLength
                | RangeError::InvalidContentLength(_)
                | RangeError::NoContentRange
                | RangeError::InvalidContentRange(_) => ErrorKind::InvalidData,
            },
            error,
        )
    }
}

fn content_length_from_content_range(
    value: &HeaderValue,
) -> Result<u64, RangeError> {
    if let Ok(s) = value.to_str()
        && let Some((unit, s)) = s.split_once(' ')
        && unit == "bytes"
        && let Some((_, s)) = s.split_once('/')
    {
        if s == "*" {
            return Err(RangeError::NoContentLength);
        }
        if let Ok(length) = s.parse() {
            return Ok(length);
        }
    }
    Err(RangeError::InvalidContentRange(value.as_bytes().to_vec()))
}
