use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use tokio_rustls::{
    rustls::{self, Certificate, PrivateKey},
    server::TlsStream,
    TlsAcceptor,
};

use rustls_pemfile::{certs, read_one, rsa_private_keys, Item};

#[tokio::main]
async fn main() {
    let certs = load_certs(&Path::new(
        "/home/elaleman/workspace/efin-proxy/files/certificate.pem",
    ))
    .unwrap();
    eprintln!("certs: {certs:?}");

    let key = match read_one(&mut BufReader::new(
        File::open("/home/elaleman/workspace/efin-proxy/files/key.pem").unwrap(),
    ))
    .unwrap()
    .unwrap()
    {
        Item::PKCS8Key(key) => PrivateKey(key),
        _ => panic!("invalid key"),
    };

    eprintln!("key: {key:?}");

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let port = 8888;

    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    loop {
        eprintln!("INFO: listening for connection");
        let (stream, _) = listener.accept().await.unwrap();
        eprintln!("INFO: connection established");

        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            handle_connection(stream, acceptor).await;
        });
    }
}

async fn handle_connection(mut stream: TcpStream, acceptor: TlsAcceptor) {
    const BUF_SIZE: usize = 1024; // TODO: select a better value
    let mut buf = vec![0; BUF_SIZE];
    let mut index = 0;

    loop {
        let read_bytes = stream.read(&mut buf[index..]).await.unwrap();
        index += read_bytes;

        if buf.len() == index {
            buf.resize(index + BUF_SIZE, 0);
            eprintln!("DEBUG: resizing buffer. New size: {}", buf.len());
        }

        eprintln!("INFO: read {read_bytes} bytes");
        eprintln!(
            "INFO: data:\n->{}<-",
            String::from_utf8_lossy(&buf[..read_bytes])
        );

        // TODO: check that hard-coded 64 value
        let mut headers = [httparse::EMPTY_HEADER; 64];

        let mut req = httparse::Request::new(&mut headers);

        let res = req.parse(&buf[..index]).unwrap();

        if res.is_complete() {
            eprintln!("INFO: request complete");
            if let Some("CONNECT") = req.method {
                let destination = req.path.unwrap();
                eprintln!("INFO: CONNECT request. Destination = {destination}");

                let dest_stream = TcpStream::connect(destination).await.unwrap();
                eprintln!("INFO: connected to destination");

                let response = "HTTP/1.1 200 OK\r\n\r\n";
                stream.write_all(response.as_bytes()).await.unwrap();

                let client_stream = acceptor.accept(stream).await.unwrap();

                tunnel_data(client_stream, dest_stream).await;
            } else {
                eprintln!("INFO: not a CONNECT request");
                eprintln!("{req:?}");
            }

            break;
        } else {
            eprintln!("INFO: request incomplete");
        }
    }
}

async fn tunnel_data(mut client_stream: TlsStream<TcpStream>, mut dest_stream: TcpStream) {
    let mut buf = [0; 4096];
    let bytes_read = client_stream.read(&mut buf).await.unwrap();

    eprintln!("INFO: read {bytes_read} bytes from client");
    eprintln!("data: ->{}<-", String::from_utf8_lossy(&buf[..bytes_read]));
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}
