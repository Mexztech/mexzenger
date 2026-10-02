use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

pub trait Transport: Read + Write + Send {
    fn try_clone_transport(&self) -> io::Result<Box<dyn Transport>>;
    fn clear_timeouts(&self) -> io::Result<()> {
        Ok(())
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
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

    fn clear_timeouts(&self) -> io::Result<()> {
        (**self).clear_timeouts()
    }

    fn set_handshake_timeouts(&self) -> io::Result<()> {
        (**self).set_handshake_timeouts()
    }
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
