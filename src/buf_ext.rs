use super::util::{unexpected_eof, unexpected_err};
use bytes::Buf;
use std::io;

pub trait BufExt: Buf {
  fn get_lenc_bytes(&mut self) -> Vec<u8> {
    self.safe_get_lenc_bytes().unwrap()
  }

  fn safe_get_lenc_bytes(&mut self) -> io::Result<Vec<u8>> {
    let len = self.safe_get_lenc_uint()? as usize;
    let mut bytes = vec![0; len];
    self.copy_to_slice(bytes.as_mut_slice());
    Ok(bytes)
  }

  fn get_eof_string(&mut self) -> String {
    self.safe_get_eof_string().unwrap()
  }

  fn safe_get_eof_string(&mut self) -> io::Result<String> {
    self.safe_get_fixed_length_string(self.remaining())
  }

  // Returns a utf-8 encoded string terminated by \0.
  fn get_null_terminated_string(&mut self) -> String {
    self.safe_null_terminated_string().unwrap()
  }

  fn safe_null_terminated_string(&mut self) -> io::Result<String> {
    let len = self
      .bytes()
      .iter()
      .position(|x| *x == 0x00)
      .unwrap_or(self.remaining());

    self.safe_get_fixed_length_string(len)
  }

  // Returns a utf-8 encoded string of length N, where N are in bytes.
  fn get_fixed_length_string(&mut self, len: usize) -> String {
    self.safe_get_fixed_length_string(len).unwrap()
  }

  fn safe_get_fixed_length_string(&mut self, len: usize) -> io::Result<String> {
    if self.remaining() >= len {
      let mut bytes = vec![0; len];
      self.copy_to_slice(bytes.as_mut_slice());

      String::from_utf8(bytes).map_err(unexpected_err)
    } else {
      Err(unexpected_eof(format!(
        "expected {}, got {}",
        len,
        self.remaining()
      )))
    }
  }

  // Returns a utf-8 encoded string of variable length. See `BufExt::get_lenc_uint`.
  fn get_lenc_string(&mut self) -> String {
    self.safe_get_lenc_string().unwrap()
  }

  fn safe_get_lenc_string(&mut self) -> io::Result<String> {
    let len = self.safe_get_lenc_uint()? as usize;
    self.safe_get_fixed_length_string(len)
  }

  // Same as get_u8, but returns an UnexpectedEof error instead of panicking when remaining < 1;
  fn safe_get_u8(&mut self) -> io::Result<u8> {
    if self.remaining() >= 1 {
      Ok(self.get_u8())
    } else {
      Err(unexpected_eof(format!(
        "expected 1, got {}",
        self.remaining()
      )))
    }
  }

  // Same as get_uint_le, but returns an UnexpectedEof error instead of panicking when remaining < 1;
  fn safe_get_uint_le(&mut self, nbytes: usize) -> io::Result<u64> {
    if self.remaining() >= nbytes {
      Ok(self.get_uint_le(nbytes))
    } else {
      Err(unexpected_eof(format!(
        "expected {}, got {}",
        nbytes,
        self.remaining()
      )))
    }
  }

  fn get_lenc_uint(&mut self) -> u64 {
    self.safe_get_lenc_uint().unwrap()
  }

  fn safe_get_lenc_uint(&mut self) -> io::Result<u64> {
    match self.safe_get_u8()? {
      0xfc => self.safe_get_uint_le(2),
      0xfd => self.safe_get_uint_le(3),
      0xfe => self.safe_get_uint_le(8),
      0xff => Err(unexpected_err("Invalid length-encoded integer value")),
      x => Ok(x as u64),
    }
  }
}

// Blanket implementations
impl<T> BufExt for T where T: Buf {}

// TODO: add remaining safe implementations

// pub trait ReadMysqlExt: ReadBytesExt {
//     /// Reads MySql's length-encoded integer.
//     fn read_lenenc_int(&mut self) -> io::Result<u64> {
//         match self.read_u8()? {
//             x if x < 0xfc => Ok(x as u64),
//             0xfc => self.read_uint::<LE>(2),
//             0xfd => self.read_uint::<LE>(3),
//             0xfe => self.read_uint::<LE>(8),
//             0xff => Err(io::Error::new(
//                 io::ErrorKind::Other,
//                 "Invalid length-encoded integer value",
//             )),
//             _ => unreachable!(),
//         }
//     }
// }

// pub trait WriteMysqlExt: WriteBytesExt {
//     /// Writes MySql's length-encoded integer.
//     fn write_lenenc_int(&mut self, x: u64) -> io::Result<u64> {
//         if x < 251 {
//             self.write_u8(x as u8)?;
//             Ok(1)
//         } else if x < 65_536 {
//             self.write_u8(0xFC)?;
//             self.write_uint::<LE>(x, 2)?;
//             Ok(3)
//         } else if x < 16_777_216 {
//             self.write_u8(0xFD)?;
//             self.write_uint::<LE>(x, 3)?;
//             Ok(4)
//         } else {
//             self.write_u8(0xFE)?;
//             self.write_uint::<LE>(x, 8)?;
//             Ok(9)
//         }
//     }

//     /// Writes MySql's length-encoded string.
//     fn write_lenenc_str(&mut self, bytes: &[u8]) -> io::Result<u64> {
//         let written = self.write_lenenc_int(bytes.len() as u64)?;
//         self.write_all(bytes)?;
//         Ok(written + bytes.len() as u64)
//     }

//     /// Writes MySql's value in binary value format.
//     fn write_bin_value(&mut self, value: &Value) -> io::Result<u64> {
//         match *value {
//             Value::NULL => Ok(0),
//             Value::Bytes(ref x) => self.write_lenenc_str(&x[..]),
//             Value::Int(x) => {
//                 self.write_i64::<LE>(x)?;
//                 Ok(8)
//             }
//             Value::UInt(x) => {
//                 self.write_u64::<LE>(x)?;
//                 Ok(8)
//             }
//             Value::Float(x) => {
//                 self.write_f64::<LE>(x)?;
//                 Ok(8)
//             }
//             Value::Date(0u16, 0u8, 0u8, 0u8, 0u8, 0u8, 0u32) => {
//                 self.write_u8(0u8)?;
//                 Ok(1)
//             }
//             Value::Date(y, m, d, 0u8, 0u8, 0u8, 0u32) => {
//                 self.write_u8(4u8)?;
//                 self.write_u16::<LE>(y)?;
//                 self.write_u8(m)?;
//                 self.write_u8(d)?;
//                 Ok(5)
//             }
//             Value::Date(y, m, d, h, i, s, 0u32) => {
//                 self.write_u8(7u8)?;
//                 self.write_u16::<LE>(y)?;
//                 self.write_u8(m)?;
//                 self.write_u8(d)?;
//                 self.write_u8(h)?;
//                 self.write_u8(i)?;
//                 self.write_u8(s)?;
//                 Ok(8)
//             }
//             Value::Date(y, m, d, h, i, s, u) => {
//                 self.write_u8(11u8)?;
//                 self.write_u16::<LE>(y)?;
//                 self.write_u8(m)?;
//                 self.write_u8(d)?;
//                 self.write_u8(h)?;
//                 self.write_u8(i)?;
//                 self.write_u8(s)?;
//                 self.write_u32::<LE>(u)?;
//                 Ok(12)
//             }
//             Value::Time(_, 0u32, 0u8, 0u8, 0u8, 0u32) => {
//                 self.write_u8(0u8)?;
//                 Ok(1)
//             }
//             Value::Time(neg, d, h, m, s, 0u32) => {
//                 self.write_u8(8u8)?;
//                 self.write_u8(if neg { 1u8 } else { 0u8 })?;
//                 self.write_u32::<LE>(d)?;
//                 self.write_u8(h)?;
//                 self.write_u8(m)?;
//                 self.write_u8(s)?;
//                 Ok(9)
//             }
//             Value::Time(neg, d, h, m, s, u) => {
//                 self.write_u8(12u8)?;
//                 self.write_u8(if neg { 1u8 } else { 0u8 })?;
//                 self.write_u32::<LE>(d)?;
//                 self.write_u8(h)?;
//                 self.write_u8(m)?;
//                 self.write_u8(s)?;
//                 self.write_u32::<LE>(u)?;
//                 Ok(13)
//             }
//         }
//     }
// }

// impl<T> ReadMysqlExt for T where T: ReadBytesExt {}
// impl<T> WriteMysqlExt for T where T: WriteBytesExt {}
