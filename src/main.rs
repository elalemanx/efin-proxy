use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    let port = 8888;

    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    loop {
        eprintln!("INFO: listening for connection");
        let (stream, _) = listener.accept().await.unwrap();
        eprintln!("INFO: connection established");

        tokio::spawn(async move {
            handle_connection(stream).await;
        });
    }
}

async fn handle_connection(mut stream: TcpStream) {
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

                tunnel_data(stream, dest_stream).await;
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

async fn tunnel_data(mut client_stream: TcpStream, mut dest_stream: TcpStream) {
    let (mut client_reader, mut client_writer) = client_stream.split();
    let (mut dest_reader, mut dest_writer) = dest_stream.split();

    let client_to_dest = tokio::io::copy(&mut client_reader, &mut dest_writer);
    let dest_to_client = tokio::io::copy(&mut dest_reader, &mut client_writer);

    let _ = tokio::try_join!(client_to_dest, dest_to_client);
}
