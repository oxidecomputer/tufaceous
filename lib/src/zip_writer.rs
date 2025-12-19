// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::Write;

use atomicwrites::AtomicFile;
use atomicwrites::OverwriteBehavior;
use bytes::Bytes;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use rawzip::CompressionMethod;
use rawzip::ZipArchiveWriter;
use rawzip::time::ZipDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub(crate) struct ZipWriter<W> {
    task: JoinHandle<Result<W, rawzip::Error>>,
    file_tx: mpsc::Sender<ZipFile>,
}

impl<W: Write + Send + 'static> ZipWriter<W> {
    pub(crate) fn new(writer: W) -> Self {
        let (file_tx, file_rx) = mpsc::channel(1);
        let task =
            tokio::task::spawn_blocking(move || write_task(writer, file_rx));
        Self { task, file_tx }
    }
}

impl ZipWriter<()> {
    pub(crate) fn create(path: &Utf8Path) -> Self {
        let file = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
        let (file_tx, file_rx) = mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            file.write(|file| write_task(file, file_rx).map(|_| ())).map_err(
                |error| match error {
                    atomicwrites::Error::User(error) => error,
                    atomicwrites::Error::Internal(error) => error.into(),
                },
            )
        });
        Self { task, file_tx }
    }
}

impl<W> ZipWriter<W> {
    pub(crate) fn new_file(
        &mut self,
        name: Utf8PathBuf,
    ) -> ZipFileBuilder<'_, W> {
        let (bytes_tx, bytes_rx) = mpsc::channel(1);
        ZipFileBuilder {
            writer: self,
            inner: ZipFile {
                name: name.into(),
                compression: Compression::none(),
                last_modified: None,
                unix_permissions: None,
                bytes_rx,
            },
            bytes_tx,
        }
    }

    pub(crate) async fn finish(self) -> Result<W, rawzip::Error> {
        drop(self.file_tx);
        self.task.await.map_err(std::io::Error::from)?
    }
}

pub(crate) struct ZipFileBuilder<'a, W> {
    writer: &'a mut ZipWriter<W>,
    inner: ZipFile,
    bytes_tx: mpsc::Sender<Bytes>,
}

impl<'a, W> ZipFileBuilder<'a, W> {
    pub(crate) fn compression(mut self, compression: Compression) -> Self {
        self.inner.compression = compression;
        self
    }

    pub(crate) fn last_modified(mut self, last_modified: ZipDateTime) -> Self {
        self.inner.last_modified = Some(last_modified);
        self
    }

    pub(crate) fn unix_permissions(mut self, unix_permissions: u32) -> Self {
        self.inner.unix_permissions = Some(unix_permissions);
        self
    }

    pub(crate) async fn start(self) -> Result<ZipDataWriter<'a, W>, SendError> {
        self.writer.file_tx.send(self.inner).await?;
        Ok(ZipDataWriter { _writer: self.writer, bytes_tx: self.bytes_tx })
    }
}

pub(crate) struct ZipDataWriter<'a, W> {
    _writer: &'a mut ZipWriter<W>,
    bytes_tx: mpsc::Sender<Bytes>,
}

impl<W> ZipDataWriter<'_, W> {
    pub(crate) async fn write(
        &mut self,
        bytes: Bytes,
    ) -> Result<(), SendError> {
        self.bytes_tx.send(bytes).await?;
        Ok(())
    }
}

struct ZipFile {
    name: String,
    compression: Compression,
    last_modified: Option<ZipDateTime>,
    unix_permissions: Option<u32>,
    bytes_rx: mpsc::Receiver<Bytes>,
}

fn write_task<W: Write>(
    writer: W,
    mut file_rx: mpsc::Receiver<ZipFile>,
) -> Result<W, rawzip::Error> {
    let mut archive = ZipArchiveWriter::new(writer);
    while let Some(mut file) = file_rx.blocking_recv() {
        let mut builder = archive.new_file(&file.name);
        if file.compression != Compression::none() {
            builder = builder.compression_method(CompressionMethod::Deflate);
        }
        if let Some(last_modified) = file.last_modified {
            builder = builder.last_modified(last_modified);
        }
        if let Some(unix_permissions) = file.unix_permissions {
            builder = builder.unix_permissions(unix_permissions);
        }
        let (mut entry, config) = builder.start()?;
        let encoder = ZipEncoder::new(&mut entry, file.compression);
        let mut writer = config.wrap(encoder);
        while let Some(bytes) = file.bytes_rx.blocking_recv() {
            writer.write_all(&bytes)?;
        }
        let (encoder, output) = writer.finish()?;
        encoder.finish()?;
        entry.finish(output)?;
    }
    archive.finish()
}

enum ZipEncoder<W: Write> {
    Store(W),
    Deflate(DeflateEncoder<W>),
}

impl<W: Write> ZipEncoder<W> {
    fn new(writer: W, compression: Compression) -> Self {
        if compression == Compression::none() {
            Self::Store(writer)
        } else {
            Self::Deflate(DeflateEncoder::new(writer, compression))
        }
    }

    fn finish(self) -> std::io::Result<W> {
        match self {
            Self::Store(writer) => Ok(writer),
            Self::Deflate(encoder) => encoder.finish(),
        }
    }
}

impl<W: Write> Write for ZipEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ZipEncoder::Store(writer) => writer.write(buf),
            ZipEncoder::Deflate(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ZipEncoder::Store(writer) => writer.flush(),
            ZipEncoder::Deflate(writer) => writer.flush(),
        }
    }
}

pub(crate) struct SendError;

impl<T> From<mpsc::error::SendError<T>> for SendError {
    fn from(_value: mpsc::error::SendError<T>) -> Self {
        Self
    }
}
