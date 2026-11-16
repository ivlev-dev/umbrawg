//! Connection state machine for the UAPI protocol.
//!
//! A connection is served by one thread at a time and may carry any number of
//! operations. Each operation produces exactly one reply terminated by an
//! empty line, matching the Go implementation.

use std::io::{BufReader, Read, Write};

use crate::error::UapiError;
use crate::parse::{parse_set_request, read_line};
use crate::serialize::{format_errno, format_get_response, format_errno_response};
use crate::types::DeviceControl;

/// Serves all operations on one accepted connection.
///
/// The connection stays open after each reply until the client closes it or
/// sends an unknown operation. An unknown operation closes the connection
/// without a reply, exactly like `wireguard-go`.
pub(crate) fn serve_stream<S: Read + Write>(
    stream: S,
    control: &dyn DeviceControl,
) -> Result<(), UapiError> {
    let mut buffered = BufReader::new(stream);

    loop {
        let Some(operation) = read_line(&mut buffered)? else {
            return Ok(());
        };

        match operation.as_str() {
            "get=1" => {
                match read_line(&mut buffered)? {
                    Some(trailing) if trailing.is_empty() => {}
                    Some(trailing) => {
                        let error = UapiError::Protocol(format!(
                            "trailing data after `get=1`: `{trailing}`"
                        ));
                        write_error(buffered.get_mut(), &error)?;
                        continue;
                    }
                    None => return Ok(()),
                }
                let response = format_get_response(&control.snapshot());
                write_response(buffered.get_mut(), &response)?;
            }
            "set=1" => {
                let result =
                    parse_set_request(&mut buffered).and_then(|request| control.apply(request));
                if let Err(error) = &result {
                    log::warn!("UAPI set=1 failed: {error}");
                }
                let response = format_errno_response(result.as_ref().err());
                write_response(buffered.get_mut(), &response)?;
            }
            other => {
                log::warn!("invalid UAPI operation: {other:?}");
                return Ok(());
            }
        }
    }
}

/// Writes an errno reply for `error`.
pub(crate) fn write_error<W: Write>(writer: &mut W, error: &UapiError) -> Result<(), UapiError> {
    log::debug!("UAPI reply with error: {error}");
    write_response(writer, &format_errno(error.code()))
}

fn write_response<W: Write>(writer: &mut W, response: &str) -> Result<(), UapiError> {
    writer.write_all(response.as_bytes())?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeviceSnapshot;

    struct FixedControl;

    impl DeviceControl for FixedControl {
        fn snapshot(&self) -> DeviceSnapshot {
            DeviceSnapshot::default()
        }

        fn apply(&self, request: crate::types::SetRequest) -> Result<(), UapiError> {
            if request.listen_port == Some(0) {
                return Err(UapiError::AddressInUse);
            }
            Ok(())
        }
    }

    #[test]
    fn handles_get_then_set_on_one_stream() {
        let mut input = std::io::Cursor::new(
            b"get=1\n\nset=1\nlisten_port=0\n\nget=1\n\n".to_vec(),
        );
        let mut output = Vec::new();
        let mut duplex = Duplex::new(&mut input, &mut output);
        serve_stream(&mut duplex, &FixedControl).expect("served");
        drop(duplex);
        let text = String::from_utf8(output).expect("utf-8");
        assert_eq!(text.matches("errno=0\n\n").count(), 2);
        assert!(text.contains("errno=-98\n\n"));
        assert!(text.contains("h1=1\n"));
    }

    #[test]
    fn closes_on_unknown_operation() {
        let mut input = std::io::Cursor::new(b"bogus\n".to_vec());
        let mut output = Vec::new();
        let mut duplex = Duplex::new(&mut input, &mut output);
        serve_stream(&mut duplex, &FixedControl).expect("served");
        drop(duplex);
        assert!(output.is_empty());
    }

    /// Minimal read/write adapter over two independent cursors.
    struct Duplex<'a> {
        input: &'a mut std::io::Cursor<Vec<u8>>,
        output: &'a mut Vec<u8>,
    }

    impl<'a> Duplex<'a> {
        fn new(
            input: &'a mut std::io::Cursor<Vec<u8>>,
            output: &'a mut Vec<u8>,
        ) -> Self {
            Self { input, output }
        }
    }

    impl Read for Duplex<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Duplex<'_> {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
