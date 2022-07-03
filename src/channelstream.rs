/***********
 * This module implements Write and Read traits for Rust mpsc message channels. This is used in the test code for mpecdsa.rs.
 * by Megan Chen
 ***********/

//! This module implements 'Write' and 'Read' traits for Rust message channels ('std::sync::mpsc'). The intended use case for this is testing network applications without using of TCP/IP.
//! 'ChannelWriter' implements the 'Write' trait for 'mpsc::Sender' and 'ChannelReader' implements the 'Read' trait for 'mpsc::Reader'.
//! We will refer to a corresponding 'ChannelWriter', 'ChannelReader' pair as a channelstream.

use std::io::prelude::*;
use std::sync::mpsc;

/// Writing half of a 'ChannelStream'. This contains a 'mpsc::Sender'. This can be cloned.
/// Messages can be sent with 'write'
#[derive(Clone)]
pub struct ChannelWriter {
    inner: mpsc::Sender<Vec<u8>>,
}

impl ChannelWriter {
    /// Constructs a new 'ChannelWriter'.
    ///
    /// # Example
    ///
    /// '''
    /// let (sender, receiver) = mpsc::channel();
    /// let channelwriter = ChannelWriter::new(sender);
    /// '''
    fn new(sender: mpsc::Sender<Vec<u8>>) -> ChannelWriter {
        ChannelWriter { inner: sender }
    }
}

impl Write for ChannelWriter {
    /// Attempts to write a message to the channelstream
    fn write(&mut self, buf: &[u8]) -> Result<usize, ::std::io::Error> {
        self.inner.send(buf.to_vec()).unwrap();
        Ok(buf.len())
    }
    /// Does nothing. This was implemented to act fulfill the trait and interface with applications that require networking
    fn flush(&mut self) -> Result<(), ::std::io::Error> {
        Ok(())
    }
}

/// Reading half of a 'ChannelStream'. This contains a 'mpsc::Receiver'.
/// Messages can be read with 'read' or 'read_exact'
pub struct ChannelReader {
    inner: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
}

impl ChannelReader {
    /// Constructs a new 'ChannelReader'.
    ///
    /// # Example
    ///
    /// '''
    /// let (sender, receiver) = mpsc::channel();
    /// let channelreader = ChannelReader::new(receiver);
    /// '''
    fn new(recv: mpsc::Receiver<Vec<u8>>) -> ChannelReader {
        ChannelReader {
            inner: recv,
            read_buf: Vec::new(),
        }
    }
}

impl Read for ChannelReader {
    /// Reads all the values that have been sent by the 'ChannelWriter'
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ::std::io::Error> {
        let mut received_vec = self.inner.recv().unwrap();
        let received_vals = &mut received_vec[..];
        buf.clone_from_slice(&received_vals);
        Ok(buf.len())
    }

    /// Adds values to 'read_buf' in the order they were sent. Then add exactly the number of bytes needed to fill 'buf'. If 'ChannelWriter' sends more than 'buf''s length, the remaining bytes will be added to 'read_buf'. If 'buf''s length is more than the length of 'buf_read' and 'ChannelWriter''s latest 'write', 'ChannelReader' will continue reading until the 'buf' is filled.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ::std::io::Error> {
        let buf_len = buf.len();
        let read_buf_len = self.read_buf.len();
        if buf_len <= read_buf_len {
            buf.clone_from_slice(&self.read_buf[..(buf_len)]);
            self.read_buf = self.read_buf.split_off(buf_len);
        } else {
            let mut received_vec = match self.inner.recv() {
                Ok(r) => r,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Channel Hung Up.",
                    ))
                }
            };
            let received_vals = &mut received_vec[..];
            self.read_buf.extend_from_slice(received_vals);
            self.read_exact(buf).unwrap();
        }
        Ok(())
    }
}

/// Constructs a new ('ChannelWriter', 'ChannelReader') pair.
///
/// # Example
///
/// '''
/// let (mut send, mut recv) = new_channelstream();
/// '''
pub fn new_channelstream() -> (ChannelWriter, ChannelReader) {
    let (s, r) = mpsc::channel();
    (ChannelWriter::new(s), ChannelReader::new(r))
}

/// Constructs n^2 ('ChannelWriter', 'ChannelReader') pairs.
///
/// # Example
///
/// '''
/// let parties = 10;
/// let (sendvec, recvvec) = spawn_n2_channelstreams(parties);
/// '''
pub fn spawn_n2_channelstreams(
    parties: usize,
) -> (
    Vec<Vec<Option<ChannelWriter>>>,
    Vec<Vec<Option<ChannelReader>>>,
) {
    let mut sendvec = Vec::with_capacity(parties);
    let mut recvvec = Vec::with_capacity(parties);
    for _ in 0..parties {
        let mut v1: Vec<Option<ChannelWriter>> = Vec::with_capacity(parties);
        let mut v2: Vec<Option<ChannelReader>> = Vec::with_capacity(parties);
        for _ in 0..parties {
            v1.push(None);
            v2.push(None);
        }
        sendvec.push(v1);
        recvvec.push(v2);
    }

    // populate send and recv vecs
    for ii in 0..parties {
        for jj in 0..parties {
            if ii < jj {
                let (writ_a, read_b) = new_channelstream();
                let (writ_b, read_a) = new_channelstream();
                sendvec[ii][jj] = Some(writ_a);
                sendvec[jj][ii] = Some(writ_b);
                recvvec[jj][ii] = Some(read_b);
                recvvec[ii][jj] = Some(read_a);
            }
        }
    }

    (sendvec, recvvec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read() {
        let (mut send, mut recv) = new_channelstream();

        let string = "hello".as_bytes();
        send.write(&string).unwrap();

        let mut buf = [0; 5];
        (&mut recv).read_exact(&mut buf[..]).unwrap();

        assert_eq!(String::from_utf8(buf.to_vec()).unwrap(), "hello");
    }

    #[test]
    fn test_read_exact1() {
        let (mut send, mut recv) = new_channelstream();

        let string = String::from("hello there good morning");

        send.write(&string.into_bytes()).unwrap();

        //create buffer
        let mut buf1 = [0; 5];
        let mut buf2 = [0; 10];
        let mut buf3 = [0; 9];
        (&mut recv).read_exact(&mut buf1[..]).unwrap();
        (&mut recv).read_exact(&mut buf2[..]).unwrap();
        (&mut recv).read_exact(&mut buf3[..]).unwrap();

        assert_eq!(String::from_utf8(buf1.to_vec()).unwrap(), "hello");
        assert_eq!(String::from_utf8(buf2.to_vec()).unwrap(), " there goo");
        assert_eq!(String::from_utf8(buf3.to_vec()).unwrap(), "d morning");
    }

    #[test]
    fn test_read_exact2() {
        let (mut send, mut recv) = new_channelstream();

        let string = String::from("hello there good morning");

        send.write(&string.into_bytes()).unwrap();

        //create buffer
        let mut buf1 = [0; 5];
        let mut buf2 = [0; 5];
        let mut buf3 = [0; 5];
        (&mut recv).read_exact(&mut buf1[..]).unwrap();
        (&mut recv).read_exact(&mut buf2[..]).unwrap();
        (&mut recv).read_exact(&mut buf3[..]).unwrap();

        assert_eq!(String::from_utf8(buf1.to_vec()).unwrap(), "hello");
        assert_eq!(String::from_utf8(buf2.to_vec()).unwrap(), " ther");
        assert_eq!(String::from_utf8(buf3.to_vec()).unwrap(), "e goo");
    }
}
