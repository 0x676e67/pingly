//! Capture chunked HTTP/1 input and parse it later without losing wire details.

use std::io;

use pingly::h1::{parse_response_head, Http1HeadBuffer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request_bytes = b"GET /api/all HTTP/1.1\r\nHoSt: localhost\r\nuSeR-aGeNt: browser\r\n\r\n";
    let mut request_capture = Http1HeadBuffer::request();

    for chunk in request_bytes.chunks(11) {
        request_capture.extend(chunk);
    }

    let request = request_capture
        .parse()?
        .into_request()
        .ok_or_else(|| io::Error::other("capture did not contain an HTTP/1 request"))?;
    let response =
        parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")?;

    println!("Request:\n{}", serde_json::to_string_pretty(&request)?);
    println!("\nResponse status: {}", response.status_code);

    Ok(())
}
