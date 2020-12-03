use std::io;

pub fn unexpected_eof<E>(e: E) -> io::Error
where
  E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  io::Error::new(io::ErrorKind::UnexpectedEof, e)
}

pub fn unexpected_err<E>(e: E) -> io::Error
where
  E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  io::Error::new(io::ErrorKind::Other, e)
}

pub fn null_terminated_pos(b: &[u8]) -> usize {
  b.iter().position(|b| *b == 0x00).unwrap_or(b.len())
}
