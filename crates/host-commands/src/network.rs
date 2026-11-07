//! Socket waits belong to asynchronous transport tasks, never command workers.
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

pub(crate) const IO_WAIT: Duration = Duration::from_secs(10);

pub(crate) struct Listener(pub tokio::net::TcpListener);
pub(crate) struct Socket {
    stream: tokio::net::TcpStream,
    write_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}
#[derive(Clone, Copy)]
pub(crate) struct Peer(pub std::net::SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, Listener>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl axum::serve::Listener for Listener {
    type Io = Socket;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Socket, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, peer)) => {
                    return (
                        Socket {
                            stream,
                            write_deadline: None,
                        },
                        peer,
                    )
                }
                Err(error) => {
                    eprintln!("runtime HTTP accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

impl tokio::io::AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl Socket {
    fn stalled(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let deadline = self
            .write_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(IO_WAIT)));
        if deadline.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime response write stalled",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl tokio::io::AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, bytes) {
            Poll::Ready(result) => {
                self.write_deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => self.stalled(cx).map_ok(|_| 0),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Ready(result) => {
                self.write_deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => self.stalled(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(crate) fn runtime() -> anyhow::Result<&'static tokio::runtime::Runtime> {
    static NETWORK: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    NETWORK
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("runtime-network")
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("network runtime: {error}"))
}
