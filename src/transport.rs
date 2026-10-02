use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

pub trait Transport: Read + Write + Send {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>>;
    fn clear_timeouts(&self) -> io::Result<()>;
    fn set_handshake_timeouts(&self) -> io::Result<()>;
}

impl Transport for TcpStream {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn clear_timeouts(&self) -> io::Result<()> {
        self.set_read_timeout(None)?;
        self.set_write_timeout(None)?;
        Ok(())
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        self.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        self.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        Ok(())
    }
}

pub fn listen(address: &str) -> io::Result<TcpListener> {
    TcpListener::bind(address)
}

pub fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    listener.accept()
}

pub fn connect(address: &str) -> io::Result<TcpStream> {
    TcpStream::connect(address)
}
