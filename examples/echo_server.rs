//! A server on TCP that echoes `echo` channels, for interop testing against other implementations.
use tokio::net::TcpListener;
use xumux::{Acceptor, Options, Session};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:0".into());
    let listener = TcpListener::bind(addr).await?;
    eprintln!("listening {}", listener.local_addr()?);
    loop {
        let (sock, _) = listener.accept().await?;
        tokio::spawn(async move {
            let (r, w) = sock.into_split();
            let Ok(s) = Session::accept(r, w, Options { ping_interval: 0, ..Options::default() }, Acceptor::default().policy(|_| Ok(()))).await else { return };
            while let Some(ch) = s.accept_channel().await {
                tokio::spawn(async move {
                    while let Ok(Some(m)) = ch.receive().await {
                        if ch.send(m.ty, m.payload).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }
}
