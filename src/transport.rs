use arti_client::{DataStream, TorClient, TorClientConfig};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::runtime::Runtime;
use yosemite::Session as I2pSession;
use yosemite::{ReadHalf as I2pReadHalf, WriteHalf as I2pWriteHalf};

pub trait Transport: Read + Write + Send {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>>;

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        Ok(())
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        let _ = duration;
        Ok(())
    }
}

pub trait TransportListener: Send {
    fn accept(&self) -> io::Result<(Box<dyn Transport>, String)>;
}

impl Transport for Box<dyn Transport> {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>> {
        (**self).try_clone_transport()
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        (**self).set_handshake_timeouts()
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(duration)
    }
}

impl Transport for TcpStream {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(30)))?;
        self.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(())
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, duration)
    }
}

struct TcpTransportListener(TcpListener);

impl TransportListener for TcpTransportListener {
    fn accept(&self) -> io::Result<(Box<dyn Transport>, String)> {
        let (stream, address) = self.0.accept()?;
        Ok((Box::new(stream), address.to_string()))
    }
}

pub fn listen(address: &str) -> io::Result<Box<dyn TransportListener>> {
    let listener = TcpListener::bind(address)?;
    Ok(Box::new(TcpTransportListener(listener)))
}

pub fn connect(address: &str) -> io::Result<Box<dyn Transport>> {
    Ok(Box::new(TcpStream::connect(address)?))
}

struct I2pTransportInner {
    runtime: Arc<Runtime>,
    reader: Mutex<I2pReadHalf>,
    writer: Mutex<I2pWriteHalf>,
    timeout: Mutex<Option<Duration>>,
}

#[derive(Clone)]
struct I2pTransport {
    inner: Arc<I2pTransportInner>,
}

impl I2pTransport {
    fn connect(address: &str) -> io::Result<Box<dyn Transport>> {
        let runtime =
            Arc::new(Runtime::new().map_err(|e| io::Error::other(format!("Tokio runtime: {e}")))?);

        let address = address.trim().to_string();
        #[cfg(debug_assertions)]
        eprintln!(
            "I2P DEST LEN={} START={:?} END={:?}",
            address.len(),
            &address[..address.len().min(20)],
            &address[address.len().saturating_sub(20)..]
        );
        let stream = runtime.block_on(async {
            let mut session = I2pSession::<yosemite::style::Stream>::new(Default::default())
                .await
                .map_err(|e| io::Error::other(format!("I2P session: {e}")))?;

            #[cfg(debug_assertions)]
            eprintln!(
                "I2P CONNECT DEBUG: len={} prefix={:?} suffix={:?}",
                address.len(),
                &address[..address.len().min(20)],
                &address[address.len().saturating_sub(20)..]
            );

            session
                .connect(&address)
                .await
                .map_err(|e| io::Error::other(format!("I2P connect: {e}")))
        })?;

        let (reader, writer) = stream
            .split()
            .ok_or_else(|| io::Error::other("I2P stream split failed"))?;

        Ok(Box::new(Self {
            inner: Arc::new(I2pTransportInner {
                runtime,
                reader: Mutex::new(reader),
                writer: Mutex::new(writer),
                timeout: Mutex::new(None),
            }),
        }))
    }

    fn run<F, T>(&self, future: F) -> io::Result<T>
    where
        F: std::future::Future<Output = io::Result<T>>,
    {
        let timeout = *self
            .inner
            .timeout
            .lock()
            .map_err(|_| io::Error::other("I2P timeout mutex poisoned"))?;

        self.inner.runtime.block_on(async move {
            match timeout {
                Some(duration) => tokio::time::timeout(duration, future).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "I2P transport timeout")
                })?,
                None => future.await,
            }
        })
    }
}

impl Transport for I2pTransport {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(self.clone()))
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        let mut timeout = self
            .inner
            .timeout
            .lock()
            .map_err(|_| io::Error::other("I2P timeout mutex poisoned"))?;
        *timeout = Some(Duration::from_secs(30));
        Ok(())
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        let mut timeout = self
            .inner
            .timeout
            .lock()
            .map_err(|_| io::Error::other("I2P timeout mutex poisoned"))?;
        *timeout = duration;
        Ok(())
    }
}

impl Read for I2pTransport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| io::Error::other("I2P reader mutex poisoned"))?;
        self.run(reader.read(buffer))
    }
}

impl Write for I2pTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("I2P writer mutex poisoned"))?;
        self.run(writer.write(buffer))
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("I2P writer mutex poisoned"))?;
        self.run(writer.flush())
    }
}

pub fn connect_i2p(address: &str) -> io::Result<Box<dyn Transport>> {
    I2pTransport::connect(address)
}

struct TorTransportInner {
    runtime: Arc<Runtime>,
    reader: Mutex<ReadHalf<DataStream>>,
    writer: Mutex<WriteHalf<DataStream>>,
    timeout: Mutex<Option<Duration>>,
}

#[derive(Clone)]
struct TorTransport {
    inner: Arc<TorTransportInner>,
}

impl TorTransport {
    fn connect(address: &str) -> io::Result<Box<dyn Transport>> {
        let runtime = Arc::new(
            Runtime::new().map_err(|error| io::Error::other(format!("Tokio runtime: {error}")))?,
        );

        let client = runtime
            .block_on(TorClient::create_bootstrapped(TorClientConfig::default()))
            .map_err(|error| io::Error::other(format!("Arti bootstrap: {error}")))?;

        let stream = runtime
            .block_on(client.connect(address))
            .map_err(|error| io::Error::other(format!("Tor connect: {error}")))?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Box::new(Self {
            inner: Arc::new(TorTransportInner {
                runtime,
                reader: Mutex::new(reader),
                writer: Mutex::new(writer),
                timeout: Mutex::new(None),
            }),
        }))
    }

    fn run<F, T>(&self, future: F) -> io::Result<T>
    where
        F: std::future::Future<Output = io::Result<T>>,
    {
        let timeout = *self
            .inner
            .timeout
            .lock()
            .map_err(|_| io::Error::other("Tor timeout mutex poisoned"))?;

        self.inner.runtime.block_on(async move {
            match timeout {
                Some(duration) => tokio::time::timeout(duration, future).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Tor transport timeout")
                })?,
                None => future.await,
            }
        })
    }
}

impl Transport for TorTransport {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(self.clone()))
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        let mut timeout = self
            .inner
            .timeout
            .lock()
            .map_err(|_| io::Error::other("Tor timeout mutex poisoned"))?;
        *timeout = Some(Duration::from_secs(30));
        Ok(())
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        let mut timeout = self
            .inner
            .timeout
            .lock()
            .map_err(|_| io::Error::other("Tor timeout mutex poisoned"))?;
        *timeout = duration;
        Ok(())
    }
}

impl Read for TorTransport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| io::Error::other("Tor reader mutex poisoned"))?;
        self.run(reader.read(buffer))
    }
}

impl Write for TorTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("Tor writer mutex poisoned"))?;
        self.run(writer.write(buffer))
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("Tor writer mutex poisoned"))?;
        self.run(writer.flush())
    }
}

pub fn connect_tor(address: &str) -> io::Result<Box<dyn Transport>> {
    TorTransport::connect(address)
}
