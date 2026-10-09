//! A fake NinjaOne for tests: answers each request from a handler and records it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::Value;

type Handler = dyn Fn(&str, &str, &Value) -> (u16, Value) + Send + 'static;

pub struct Fake {
    pub url: String,
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Fake {
    /// Serves until the test process ends; `handler` gets method, path with query, and the JSON body
    /// (`Null` when there is none) and returns the status and JSON reply.
    pub fn start(handler: impl Fn(&str, &str, &Value) -> (u16, Value) + Send + 'static) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        let handler: Box<Handler> = Box::new(handler);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut words = line.split_whitespace();
                let (method, path) = (
                    words.next().unwrap_or("").to_owned(),
                    words.next().unwrap_or("").to_owned(),
                );
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header.trim().is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let (status, reply) = handler(&method, &path, &body);
                log.lock().unwrap().push((method, path, body));
                let text = if reply.is_null() {
                    String::new()
                } else {
                    reply.to_string()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        Fake { url, requests }
    }

    /// The bodies of the requests made with `method` to `path`, in order.
    pub fn requests_to(&self, method: &str, path: &str) -> Vec<Value> {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .filter(|(m, p, _)| m == method && p == path)
            .map(|(_, _, body)| body.clone())
            .collect()
    }
}
