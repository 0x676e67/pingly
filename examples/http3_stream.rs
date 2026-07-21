use pingly::h3::{parse_request_stream, Frame};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A decrypted request stream containing one stateless QPACK HEADERS frame.
    let mut stream = vec![0x01, 0x1d, 0x00, 0x00, 0xd1, 0x51, 0x0a];
    stream.extend_from_slice(b"/api/http3");
    stream.extend_from_slice(&[0x5f, 0x50, 0x0b]);
    stream.extend_from_slice(b"pingly-test");

    for frame in parse_request_stream(&stream)? {
        if let Frame::Headers(headers) = frame {
            for field in headers.headers {
                println!(
                    "{}: {}",
                    String::from_utf8_lossy(&field.name),
                    String::from_utf8_lossy(&field.value)
                );
            }
        }
    }

    Ok(())
}
