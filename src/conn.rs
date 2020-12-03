use bytes::{Buf, BufMut, BytesMut};
use std::io;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{lookup_host, TcpStream};
use url::{Host as UrlHost, Url};

use super::protocol::{
  AuthResponse, CapabilityFlags, CharacterSet, ColumnDefinition, ColumnDefinitionResponse, Command,
  Handshake, HandshakeResponse, Packet, Payload, QueryResponse, Row, RowResponse, ServerError,
  ServerOk, StatusFlags, CACHING_SHA2_PASSWORD_PLUGIN_NAME, MAX_PAYLOAD_LEN,
  MYSQL_NATIVE_PASSWORD_PLUGIN_NAME,
};
use super::value::Value;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
  #[error("Unable to resolve address due to IO error")]
  Io(#[from] io::Error),
  #[error("Unable to resolve address, host `{0}` is unreachable")]
  UnreachableHost(String),
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
  #[error("Unable to complete handshake due to codec error")]
  Codec(#[from] CodecError),

  #[error("io err")]
  Io(#[from] io::Error),

  #[error("ZZZZ")]
  ServerError(#[from] ServerError2),
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
  #[error("unexpected packet")]
  UnexpectedPacket,
  #[error("io err")]
  Io(#[from] io::Error),
  #[error("woeiruwer")]
  ConnectionResetByPeer,
  #[error("WERWER")]
  PacketOutOfSync,
  #[error("!@#!@#")]
  ConnectionClosed,
  #[error("WERWERzz")]
  ServerError(#[from] ServerError2),
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError2 {
  #[error("WEWW")]
  Something,
}

#[derive(Debug)]
pub struct ConnectionOptions {
  host: Option<Host>,
  port: u16,
  user: Option<String>,
  password: Option<String>,
  db_name: Option<String>,
}

impl ConnectionOptions {
  fn user(&self) -> Option<&str> {
    self.user.as_ref().map(String::as_str)
  }
  fn has_user_name(&self) -> bool {
    self.user.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
  }
  fn db_name(&self) -> Option<&str> {
    self.db_name.as_ref().map(String::as_str)
  }
  fn has_db_name(&self) -> bool {
    self
      .db_name
      .as_ref()
      .map(|s| !s.is_empty())
      .unwrap_or(false)
  }
  fn password(&self) -> Option<&str> {
    self.password.as_ref().map(String::as_str)
  }
  fn pid(&self) -> usize {
    todo!()
  }
  fn hostname(&self) -> &str {
    todo!()
  }
  fn compression_enabled(&self) -> bool {
    false
  }
  fn ssl_enabled(&self) -> bool {
    false
  }
}

impl Default for ConnectionOptions {
  fn default() -> Self {
    Self {
      host: Some(Host::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
      port: 3306,
      user: Some("root".into()),
      password: None,
      db_name: None,
    }
  }
}

#[derive(Debug)]
pub enum Host {
  Domain(String),
  V4(std::net::Ipv4Addr),
  V6(std::net::Ipv6Addr),
}

impl From<Url> for ConnectionOptions {
  fn from(url: Url) -> Self {
    let port = url.port().unwrap_or(3306);
    let host = url.host().map(Into::into);
    let user = Some(url.username().to_string());
    let password = url.password().map(Into::into);
    let db_name = None;
    Self {
      host,
      port,
      user,
      password,
      db_name,
    }
  }
}

impl From<UrlHost<&str>> for Host {
  fn from(url_host: UrlHost<&str>) -> Self {
    match url_host {
      UrlHost::Domain(s) => Host::Domain(s.into()),
      UrlHost::Ipv4(ipv4) => Host::V4(ipv4),
      UrlHost::Ipv6(ipv6) => Host::V6(ipv6),
    }
  }
}

pub struct Connection {
  stream: TcpStream,
  capabilities: CapabilityFlags,
  status_flags: StatusFlags,
  character_set: CharacterSet,
  buffer: BytesMut,
  sequence_id: u8,
  last_command_id: u8,
  opts: ConnectionOptions,
  max_packet_size: u32,
  warnings: u16,
  affected_rows: u64,
  last_inserted_id: u64,
}

impl Connection {
  pub async fn connect(opts: impl Into<ConnectionOptions>) -> Result<Self, ConnectError> {
    let opts = opts.into();
    let port = opts.port;
    let addr = match opts.host {
      Some(Host::Domain(ref domain)) => {
        let mut hosts = lookup_host(format!("{}:{}", domain, port)).await?;
        hosts
          .next()
          .ok_or(ConnectError::UnreachableHost(domain.clone()))
      }
      Some(Host::V4(ipv4)) => Ok(SocketAddrV4::new(ipv4, port).into()),
      Some(Host::V6(ipv6)) => Ok(SocketAddrV6::new(ipv6, port, 0, 0).into()),
      None => Ok(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port).into()),
    }?;

    let stream = TcpStream::connect(&addr).await?;
    let capabilities = CapabilityFlags::empty();
    let status_flags = StatusFlags::empty();
    let character_set = CharacterSet::UTF8MB4;
    let buffer = BytesMut::with_capacity(4 * 1024);
    let sequence_id = 0;

    let mut connection = Connection {
      stream,
      capabilities,
      buffer,
      sequence_id,
      last_command_id: 0,
      last_inserted_id: 0,
      warnings: 0,
      affected_rows: 0,
      max_packet_size: 16_777_216, // 16MB
      opts,
      status_flags,
      character_set,
    };
    connection.handshake().await.unwrap();

    Ok(connection)
  }

  pub async fn handshake(&mut self) -> Result<(), HandshakeError> {
    // https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
    let packet = self.read_payload().await?;

    match packet.as_handshake_response(self.capabilities)? {
      HandshakeResponse::Success(p) => self.handle_handshake(p).await.map_err(Into::into),
      HandshakeResponse::Failure(p) => Err(self.handle_server_error(p).into()),
    }
  }

  fn handle_server_error(&mut self, err: ServerError) -> ServerError2 {
    panic!("err = {:?}", err);
  }

  async fn handle_handshake(&mut self, p: Handshake) -> Result<(), HandshakeError> {
    if p.protocol_version() != 10u8 {
      panic!("not supported")
    }

    if !p
      .capabilities()
      .contains(CapabilityFlags::CLIENT_PROTOCOL_41)
    {
      panic!("not supported")
    }

    // Intersection between what the server supports, and what our client supports.
    self.capabilities = p.capabilities() & default_capabilities(&self.opts);
    self.status_flags = p.status_flags();
    self.character_set = p.character_set();

    // TODO: update connection state.
    // self.capabilities = p.capabilities() & self.opts.default_capabilities();
    // fn handle_handshake(&mut self, hp: &HandshakePacket<'_>) {
    //     self.capability_flags = hp.capabilities() & self.get_client_flags();
    //     self.status_flags = hp.status_flags();
    //     self.connection_id = hp.connection_id();
    //     self.character_set = hp.default_collation();
    //     self.server_version = hp.server_version_parsed();
    //     self.mariadb_server_version = hp.maria_db_server_version_parsed();
    // }

    if self.opts.ssl_enabled() {
      // TODO: ssl
      panic!("not supported");
    }

    let nonce = p.nonce();
    let auth_plugin_name = p.auth_plugin_name();
    let auth_data = scramble_password(auth_plugin_name, self.opts.password(), &nonce)?;
    self
      .write_handshake_response(auth_plugin_name, auth_data)
      .await?;
    self.authenticate(auth_plugin_name, &nonce).await?;

    if self.capabilities.contains(CapabilityFlags::CLIENT_COMPRESS) {
      // TODO: wrap stream to a compressed stream.
      panic!("not supported");
    }

    Ok(())
  }

  pub async fn query(&mut self, query: impl AsRef<str>) -> Result<QueryResults, CodecError> {
    // TODO: Vec<T> could potentially be a stream if we want to support multi result sets...
    self
      .write_command(Command::COM_QUERY, query.as_ref().as_bytes())
      .await?;
    self.read_results().await
  }

  pub async fn first(&mut self, query: impl AsRef<str>) -> Result<Option<()>, CodecError> {
    self.query(query).await.map(|r| r.first())
  }

  pub async fn ping(&mut self) -> Result<(), CodecError> {
    self.write_command(Command::COM_PING, &[]).await?;
    self.read_ok().await
  }

  async fn write_command(&mut self, cmd: Command, payload: &[u8]) -> Result<(), CodecError> {
    self.sequence_id = 0;
    self.last_command_id = cmd as u8;

    let mut b = BytesMut::with_capacity(1 + payload.len());
    b.put_u8(cmd as u8);
    b.put(payload);

    self.write_payload(&b[..]).await
  }

  async fn write_payload(&mut self, payload: &[u8]) -> Result<(), CodecError> {
    for chunk in payload.chunks(MAX_PAYLOAD_LEN) {
      let mut b = BytesMut::with_capacity(4 + chunk.len());
      b.put_uint_le(chunk.len() as u64, 3);
      b.put_u8(self.sequence_id);
      b.put(chunk);

      println!(">> {:02X?}", chunk);

      self.sequence_id = self.sequence_id.wrapping_add(1);
      self.stream.write(&b[..]).await?;
    }

    Ok(())
  }

  async fn read_ok(&mut self) -> Result<(), CodecError> {
    let payload = self.read_payload().await?;
    let ok = payload.as_server_ok(self.capabilities)?;

    self.handle_ok(ok);
    Ok(())
  }

  async fn read_results(&mut self) -> Result<QueryResults, CodecError> {
    let payload = self.read_payload().await?;
    let query_response = payload.as_query_response(self.capabilities)?;

    match query_response {
      QueryResponse::Success(p) => {
        self.handle_ok(p);
        Ok(QueryResults::default())
      }
      QueryResponse::Failure(p) => {
        let err = self.handle_server_error(p);
        Err(err.into())
      }
      QueryResponse::ResultSet(column_count) => {
        let columns = self.read_columns(column_count as usize).await?;
        let rows = self.read_rows(&columns).await?;
        let query_results = QueryResults { columns, rows };
        Ok(query_results)
      }
      QueryResponse::LocalInfile(p) => todo!("not supported"),
    }
  }

  async fn read_columns(
    &mut self,
    column_count: usize,
  ) -> Result<Vec<ColumnDefinition>, CodecError> {
    // https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::Resultset
    let mut columns = Vec::with_capacity(column_count);
    for i in 0..column_count {
      let payload = self.read_payload().await?;
      let column_definition_response = payload.as_column_definition_response(self.capabilities)?;
      match column_definition_response {
        ColumnDefinitionResponse::Success(ok) => {
          self.handle_ok(ok);
          break;
        }
        ColumnDefinitionResponse::ColumnDefinition(column) => {
          columns.push(column);
        }
      }
    }
    Ok(columns)
  }

  async fn read_rows(&mut self, columns: &Vec<ColumnDefinition>) -> Result<Vec<Row>, CodecError> {
    // https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::ResultsetRow
    let mut rows = Vec::new();
    loop {
      let payload = self.read_payload().await?;
      let row_response = payload.as_row_response(self.capabilities, &columns)?;

      match row_response {
        RowResponse::Success(ok) => {
          self.handle_ok(ok);
          break;
        }
        RowResponse::Row(row) => {
          rows.push(row);
        }
      }
    }
    Ok(rows)
  }

  async fn authenticate(
    &mut self,
    auth_plugin_name: &str,
    nonce: &[u8],
  ) -> Result<(), HandshakeError> {
    let payload = self.read_payload().await?;
    let auth_response = payload.as_auth_response(self.capabilities)?;

    match (auth_plugin_name, auth_response) {
      (MYSQL_NATIVE_PASSWORD_PLUGIN_NAME, AuthResponse::Success(p)) => {
        self.handle_ok(p);
        Ok(())
      }
      (MYSQL_NATIVE_PASSWORD_PLUGIN_NAME, AuthResponse::AuthSwitch) => {
        todo!();
      }
      (CACHING_SHA2_PASSWORD_PLUGIN_NAME, AuthResponse::Success(p)) => todo!(),
      (CACHING_SHA2_PASSWORD_PLUGIN_NAME, AuthResponse::AuthSwitch) => todo!(),
      (CACHING_SHA2_PASSWORD_PLUGIN_NAME, AuthResponse::AuthMoreData) => todo!(),
      (_, AuthResponse::Failure(p)) => {
        let err = self.handle_server_error(p);
        Err(err.into())
      }
      (custom, _) => panic!("custom not supported"),
    }
  }

  fn handle_ok(&mut self, ok: ServerOk) {
    self.affected_rows = ok.affected_rows();
    self.last_inserted_id = ok.last_inserted_id();
    self.status_flags = ok.status_flags().unwrap_or(StatusFlags::empty());
    self.warnings = ok.warnings().unwrap_or(0);
  }

  async fn read_payload(&mut self) -> Result<Payload, CodecError> {
    let packet = self.read_packet().await?;
    self.check_sequence_id(packet.sequence_id())?;
    let payload = packet.as_payload();
    println!("<< {:02X?}", payload.as_bytes());
    Ok(payload)
  }

  pub fn check_sequence_id(&mut self, sequence_id: u8) -> Result<(), CodecError> {
    if self.sequence_id != sequence_id {
      return Err(CodecError::PacketOutOfSync);
    }

    self.sequence_id = self.sequence_id.wrapping_add(1);
    Ok(())
  }

  async fn write_handshake_response(
    &mut self,
    auth_plugin_name: &str,
    scrambled_data: Option<Vec<u8>>,
  ) -> Result<(), CodecError> {
    let auth_plugin_name = auth_plugin_name.as_bytes();
    let auth_plugin_len = auth_plugin_name.len();
    let user = self.opts.user().map(str::as_bytes);
    let db_name = self.opts.db_name().map(str::as_bytes);
    let user_len = user.map(|x| x.len()).unwrap_or(0);
    let db_name_len = db_name.map(|x| x.len()).unwrap_or(0);
    let scramble_data_len = scrambled_data.as_ref().map(Vec::len).unwrap_or(0);

    let mut payload_len = 4 + 4 + 1 + 23 + 1 + scramble_data_len + auth_plugin_len;
    if user_len > 0 {
      payload_len += user_len + 1;
    }
    if db_name_len > 0 {
      payload_len += db_name_len + 1;
    }

    let mut b = BytesMut::with_capacity(payload_len);
    b.put_u32_le(self.capabilities.bits());
    b.put_u32_le(self.max_packet_size);
    b.put_u8(default_character_set() as u8);
    b.put(&[0; 23][..]);

    if let Some(user) = user {
      b.put(user);
      b.put_u8(0);
    }

    b.put_u8(scramble_data_len as u8);
    if let Some(scrable_data) = scrambled_data {
      b.put(scrable_data.as_slice());
    }

    if let Some(db_name) = db_name {
      b.put(db_name);
      b.put_u8(0);
    }

    b.put(auth_plugin_name);
    b.put_u8(0);

    // TODO: connection attributes (e.g. name of the client, version, etc...)
    self.write_payload(&b[..]).await
  }

  // TODO: move this out of here...
  async fn read_packet(&mut self) -> Result<Packet, CodecError> {
    loop {
      let mut buf = Cursor::new(&self.buffer[..]);

      // We have enough data to parse a complete MYSQL packet.
      if Packet::check(&mut buf) {
        buf.set_position(0);
        let packet = Packet::parse(&mut buf)?;
        let len = buf.position() as usize;
        self.buffer.advance(len);
        return Ok(packet);
      }

      // There is not enough buffered data to read a frame. Attempt to read more data from the socket.
      //
      // On success, the number of bytes is returned. `0` indicates "end of stream".
      if self.stream.read_buf(&mut self.buffer).await? == 0 {
        if self.buffer.is_empty() {
          return Err(CodecError::ConnectionClosed);
        } else {
          return Err(CodecError::ConnectionResetByPeer);
        }
      }
    }
  }

  pub async fn into_binlog_stream(mut self) -> Result<BinlogStream, CodecError> {
    let r = self.first("show master status").await?;
    Ok(BinlogStream)
  }

  // pub fn binlog_reader(mut self) -> MyResult<Box<(FnMut() -> MyResult<Vec<u8>>)>> {
  //       let (file_name, position) = self.first("show master status").and_then(|result| {
  //           let (file_name, position, _, _, _) : (String, u32, String, String, String) = from_row(result.unwrap());
  //           Ok((file_name, position))
  //       })?;

  //       self.binlog_reader_from_position(file_name, position)
  //   }

  //   pub fn binlog_reader_from_position(mut self, file_name: String, position: u32) -> MyResult<Box<(FnMut() -> MyResult<Vec<u8>>)>> {
  //       self._disable_checksum()?;
  //       self._write_register_slave_command()?;
  //       self._write_binlog_dump_command(file_name, position)?;

  //       Ok(Box::new(move || { self.read_packet() }))
  //   }

  //   fn _disable_checksum(&mut self) -> MyResult<()> {
  //       let checksum = self.get_system_var("binlog_checksum")
  //           .map(from_value::<String>)
  //           .unwrap_or("NONE".to_owned());

  //       match checksum.as_ref() {
  //           "NONE" => Ok(()),
  //           "CRC32" => {
  //               self.query("SET @master_binlog_checksum='NONE'")?;
  //               Ok(())
  //           }
  //           _ => Err(DriverError(UnexpectedPacket)),
  //       }
  //   }

  //   fn _write_register_slave_command(&mut self) -> MyResult<Vec<Column>> {
  //       match hostname::get_hostname() {
  //           Some(local_hostname) => {
  //               let user = self.opts.get_user().unwrap();
  //               let password = self.opts.get_pass().unwrap_or_default();
  //               let server_id = self.opts.get_server_id();
  //               let mut buf = vec![0; 4+1+4+1+local_hostname.len()+1+user.len()+1+password.len()+2+4+4];

  //               {
  //                   let mut writer = &mut buf[..];
  //                   writer.write_u32::<LE>(server_id)?;
  //                   writer.write_u8(local_hostname.len() as u8)?;
  //                   writer.write_all(local_hostname.as_bytes())?;
  //                   writer.write_u8(user.len() as u8)?;
  //                   writer.write_all(user.as_bytes())?;
  //                   writer.write_u8(password.len() as u8)?;
  //                   writer.write_all(password.as_bytes())?;
  //                   writer.write_u16::<LE>(self.opts.get_tcp_port())?;
  //                   writer.write_u32::<LE>(0u32)?;
  //                   writer.write_u32::<LE>(0u32)?;
  //               }

  //               self.write_command_data(Command::COM_REGISTER_SLAVE, &buf)?;
  //               self.handle_result_set()
  //           }
  //           None => Err(DriverError(UnexpectedPacket)),
  //       }
  //   }

  //   fn _write_binlog_dump_command(&mut self, file_name: String, position: u32) -> MyResult<Vec<Column>> {
  //       let server_id = self.opts.get_server_id();
  //       let mut buf = vec![0; 4 + 4 + 2 + 4 + file_name.len() + 1];

  //       {
  //           let mut writer = &mut buf[..];
  //           writer.write_u32::<LE>(position)?;
  //           writer.write_u16::<LE>(0u16)?;
  //           writer.write_u32::<LE>(server_id)?;
  //           writer.write_all(file_name.as_bytes())?;
  //       }

  //       self.write_command_data(Command::COM_BINLOG_DUMP, &buf)?;
  //       self.handle_result_set()
  //   }
}

fn default_character_set() -> CharacterSet {
  // TODO: not 100% sure, but seems to depends on the server version...
  CharacterSet::UTF8
}

// Defines the default capabilities that our client support.
fn default_capabilities(opts: &ConnectionOptions) -> CapabilityFlags {
  let mut capabilities = CapabilityFlags::CLIENT_PROTOCOL_41
    | CapabilityFlags::CLIENT_SECURE_CONNECTION
    | CapabilityFlags::CLIENT_LONG_PASSWORD
    | CapabilityFlags::CLIENT_PLUGIN_AUTH
    | CapabilityFlags::CLIENT_LONG_FLAG
    // | CapabilityFlags::CLIENT_CONNECT_ATTRS // TODO: ...
    | CapabilityFlags::CLIENT_DEPRECATE_EOF;

  if opts.compression_enabled() {
    capabilities.insert(CapabilityFlags::CLIENT_COMPRESS);
  }

  if opts.has_db_name() {
    capabilities.insert(CapabilityFlags::CLIENT_CONNECT_WITH_DB);
  }

  if opts.ssl_enabled() {
    capabilities.insert(CapabilityFlags::CLIENT_SSL);
  }

  capabilities
}

pub fn scramble_password(
  auth_plugin_name: &str,
  password: Option<&str>,
  nonce: &[u8],
) -> io::Result<Option<Vec<u8>>> {
  match (password, auth_plugin_name) {
    (Some(password), MYSQL_NATIVE_PASSWORD_PLUGIN_NAME) => {
      Ok(super::scramble::scramble_native(nonce, password.as_bytes()).map(|x| x.to_vec()))
    }
    (Some(password), CACHING_SHA2_PASSWORD_PLUGIN_NAME) => {
      Ok(super::scramble::scramble_sha256(nonce, password.as_bytes()).map(|x| x.to_vec()))
    }
    (Some(custom_plugin_name), _) => unimplemented!(),
    (None, _) => Ok(None),
  }
}

pub struct BinlogStream;

pub struct QueryResults {
  columns: Vec<ColumnDefinition>,
  rows: Vec<Row>,
}

impl QueryResults {
  pub fn first(&self) -> Option<()> {
    None
  }
}

impl Default for QueryResults {
  fn default() -> Self {
    let columns = Vec::new();
    let rows = Vec::new();
    Self { columns, rows }
  }
}