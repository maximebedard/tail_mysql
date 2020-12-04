use bytes::{Buf, BufMut, BytesMut};
use futures::stream::{self, Stream};
use std::io;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{lookup_host, TcpStream};
use url::{Host as UrlHost, Url};

use super::protocol::{
  AuthResponse, BinlogDumpFlags, CapabilityFlags, CharacterSet, Column, ColumnDefinitionResponse,
  Command, GenericResponse, Handshake, HandshakeResponse, Packet, Payload, QueryResponse, Row,
  RowResponse, ServerError, ServerOk, StatusFlags, CACHING_SHA2_PASSWORD_PLUGIN_NAME,
  MAX_PAYLOAD_LEN, MYSQL_NATIVE_PASSWORD_PLUGIN_NAME,
};
use super::value::Value;

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
  #[error("Failed due to IO error")]
  Io(#[from] io::Error),
  #[error("Unable to resolve address, host `{0}` is unreachable")]
  UnreachableHost(String),
  #[error("Unexpected packet")]
  UnexpectedPacket,
  #[error("Connection was reseted by MYSQL")]
  ConnectionResetByPeer,
  #[error("Packets sequence_id are out of sync with MYSQL")]
  PacketOutOfSync,
  #[error("Connection was closed by the client")]
  ConnectionClosed,
  #[error("Failed due to server error")]
  UpstreamError(#[from] UpstreamError),
  #[error("Failed to start binlog stream, replication is not configured.")]
  ReplicationDisabled,
}

type DriverResult<T> = Result<T, DriverError>;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
  #[error("todo")]
  Something,
}

#[derive(Debug)]
pub struct ConnectionOptions {
  host: Option<Host>,
  port: u16,
  user: Option<String>,
  password: Option<String>,
  db_name: Option<String>,
  hostname: Option<String>,
  server_id: Option<u32>,
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
      hostname: None,
      server_id: None,
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
    let hostname = None;
    let server_id = None;
    Self {
      host,
      port,
      user,
      password,
      db_name,
      hostname,
      server_id,
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

pub struct ReplicationOptions {
  hostname: Option<String>,
  user: Option<String>,
  password: Option<String>,
  server_id: u32,
  port: u16,
}

impl Default for ReplicationOptions {
  fn default() -> Self {
    let hostname = None;
    let user = None;
    let password = None;
    let server_id = 1;
    let port = 3306;
    Self {
      hostname,
      user,
      password,
      server_id,
      port,
    }
  }
}

impl ReplicationOptions {
  pub fn server_id(&self) -> u32 {
    self.server_id
  }

  pub fn port(&self) -> u16 {
    self.port
  }

  pub fn hostname(&self) -> Option<&str> {
    self.hostname.as_ref().map(String::as_str)
  }

  pub fn password(&self) -> Option<&str> {
    self.password.as_ref().map(String::as_str)
  }

  pub fn user(&self) -> Option<&str> {
    self.user.as_ref().map(String::as_str)
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
  /// Establish a connection to MYSQL.
  pub async fn connect(opts: impl Into<ConnectionOptions>) -> DriverResult<Self> {
    let opts = opts.into();
    let port = opts.port;
    let addr = match opts.host {
      Some(Host::Domain(ref domain)) => {
        let mut hosts = lookup_host(format!("{}:{}", domain, port)).await?;
        hosts
          .next()
          .ok_or(DriverError::UnreachableHost(domain.clone()))
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

  pub async fn handshake(&mut self) -> DriverResult<()> {
    // https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
    let packet = self.read_payload().await?;

    match packet.as_handshake_response(self.capabilities)? {
      HandshakeResponse::Success(p) => self.handle_handshake(p).await.map_err(Into::into),
      HandshakeResponse::Failure(p) => Err(self.handle_server_error(p).into()),
    }
  }

  fn handle_server_error(&mut self, err: ServerError) -> UpstreamError {
    panic!("err = {:?}", err);
  }

  async fn handle_handshake(&mut self, p: Handshake) -> DriverResult<()> {
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
    // potentially keep the server version too?

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

  /// Send a text query to MYSQL and returns a result set.
  pub async fn query(&mut self, query: impl AsRef<str>) -> DriverResult<QueryResults> {
    // TODO: Vec<T> could potentially be a stream if we want to support multi result sets...
    self
      .write_command(Command::COM_QUERY, query.as_ref().as_bytes())
      .await?;
    self.read_results().await
  }

  /// Send a text query to MYSQL and yield only the first result.
  pub async fn pop(&mut self, query: impl AsRef<str>) -> DriverResult<Option<QueryResult>> {
    self.query(query).await.map(QueryResults::pop)
  }

  pub async fn ping(&mut self) -> DriverResult<()> {
    self.write_command(Command::COM_PING, &[]).await?;
    self.read_ok().await
  }

  async fn write_command(&mut self, cmd: Command, payload: &[u8]) -> DriverResult<()> {
    self.sequence_id = 0;
    self.last_command_id = cmd as u8;

    let mut b = BytesMut::with_capacity(1 + payload.len());
    b.put_u8(cmd as u8);
    b.put(payload);

    self.write_payload(&b[..]).await
  }

  async fn write_payload(&mut self, payload: &[u8]) -> DriverResult<()> {
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

  async fn read_ok(&mut self) -> DriverResult<()> {
    let payload = self.read_payload().await?;
    let ok = payload.as_server_ok(self.capabilities)?;

    self.handle_ok(ok);
    Ok(())
  }

  async fn read_generic_reponse(&mut self) -> DriverResult<()> {
    let payload = self.read_payload().await?;
    let generic_response = payload.as_generic_response(self.capabilities)?;

    match generic_response {
      GenericResponse::ServerOk(ok) => {
        self.handle_ok(ok);
        Ok(())
      }
      GenericResponse::ServerError(err) => Err(self.handle_server_error(err).into()),
    }
  }

  async fn read_results(&mut self) -> DriverResult<QueryResults> {
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
        let query_results = QueryResults {
          columns: Arc::new(columns),
          rows,
        };
        Ok(query_results)
      }
      QueryResponse::LocalInfile(p) => todo!("not supported"),
    }
  }

  async fn read_columns(&mut self, column_count: usize) -> DriverResult<Vec<Column>> {
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

  async fn read_rows(&mut self, columns: &Vec<Column>) -> DriverResult<Vec<Row>> {
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

  async fn authenticate(&mut self, auth_plugin_name: &str, nonce: &[u8]) -> DriverResult<()> {
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

  async fn read_payload(&mut self) -> DriverResult<Payload> {
    let packet = self.read_packet().await?;
    self.check_sequence_id(packet.sequence_id())?;
    let payload = packet.as_payload();
    println!("<< {:02X?}", payload.as_bytes());
    Ok(payload)
  }

  fn check_sequence_id(&mut self, sequence_id: u8) -> DriverResult<()> {
    if self.sequence_id != sequence_id {
      return Err(DriverError::PacketOutOfSync);
    }

    self.sequence_id = self.sequence_id.wrapping_add(1);
    Ok(())
  }

  async fn write_handshake_response(
    &mut self,
    auth_plugin_name: &str,
    scrambled_data: Option<Vec<u8>>,
  ) -> DriverResult<()> {
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
  async fn read_packet(&mut self) -> DriverResult<Packet> {
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
          return Err(DriverError::ConnectionClosed);
        } else {
          return Err(DriverError::ConnectionResetByPeer);
        }
      }
    }
  }

  async fn get_system_variable(
    &mut self,
    var: impl AsRef<str>,
  ) -> DriverResult<Option<QueryResult>> {
    self.pop(format!("SELECT @@{}", var.as_ref())).await
  }

  /// Returns a stream that yields binlog events, starting from the very beginning of the current log.
  pub async fn binlog_stream<'a>(
    &'a mut self,
    replication_opts: impl Into<ReplicationOptions>,
  ) -> DriverResult<impl Stream<Item = DriverResult<BinlogEvent>> + 'a> {
    let master_status = self.pop("SHOW MASTER STATUS").await.and_then(|r| {
      r.map(Ok)
        .unwrap_or_else(|| Err(DriverError::ReplicationDisabled))
    })?;

    let values = master_status.values();
    println!("{:?}", values);
    let file = values[0].as_str().expect("Must be string").to_string();
    let position = values[1].as_u32().expect("Must be u32");
    let opts = replication_opts.into();
    println!("binlog file = {}", file);
    println!("position = {}", position);
    self.resume_binlog_stream(opts, file, position).await
  }

  /// Returns a stream that yields binlog events, starting from a given position and binlog file.
  pub async fn resume_binlog_stream<'a>(
    &'a mut self,
    replication_opts: impl Into<ReplicationOptions>,
    file: impl AsRef<str>,
    position: u32,
  ) -> DriverResult<impl Stream<Item = DriverResult<BinlogEvent>> + 'a> {
    let replication_opts = replication_opts.into();
    let server_id = replication_opts.server_id();

    self.ensure_checksum_is_disabled().await?;
    self.register_as_replica(&replication_opts).await?;
    self.dump_binlog(server_id, file, position).await?;

    let stream = futures::stream::unfold(self, |conn| async move {
      conn
        .read_binlog_event()
        .await
        .transpose()
        .map(|evt| (evt, conn))
    });

    Ok(stream)
  }

  async fn read_binlog_event(&mut self) -> DriverResult<Option<BinlogEvent>> {
    let payload = self.read_payload().await?;
    // let binlog_response = payload.as_binlog_response()?;
    todo!()
  }

  async fn ensure_checksum_is_disabled(&mut self) -> DriverResult<()> {
    self.query("SET @master_binlog_checksum='NONE'").await?;
    Ok(())
    // TODO: it most likely better to check the value before actually trying to set it.

    // let checksum = self.get_system_variable("binlog_checksum")
    //   .await
    //   .and_then(QueryResult::value_as_str);

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
  }

  async fn register_as_replica(
    &mut self,
    replication_opts: &ReplicationOptions,
  ) -> DriverResult<()> {
    let hostname = replication_opts.hostname().unwrap_or("").as_bytes();
    let user = replication_opts.user().unwrap_or("").as_bytes();
    let password = replication_opts.password().unwrap_or("").as_bytes();
    let server_id = replication_opts.server_id();
    let port = replication_opts.port();

    let payload_len = 4 + 1 + hostname.len() + 1 + user.len() + 1 + password.len() + 2 + 4 + 4;

    let mut b = BytesMut::with_capacity(payload_len);

    b.put_u32_le(server_id);
    b.put_u8(hostname.len() as u8);
    b.put(hostname);
    b.put_u8(user.len() as u8);
    b.put(user);
    b.put_u8(password.len() as u8);
    b.put(password);
    b.put_u16_le(port);
    b.put_u32(0); // replication_rank ignored.
    b.put_u32(0); // master id is usually 0.

    self
      .write_command(Command::COM_REGISTER_SLAVE, &b[..])
      .await?;
    self.read_generic_reponse().await?;

    Ok(())
  }

  async fn dump_binlog(
    &mut self,
    server_id: u32,
    file: impl AsRef<str>,
    position: u32,
  ) -> DriverResult<()> {
    let file = file.as_ref().as_bytes();
    let file_len = file.len();

    let payload_len = 4 + 2 + 4 + file_len + 1;

    let mut b = BytesMut::with_capacity(payload_len);
    b.put_u32_le(position);
    b.put_u16_le(BinlogDumpFlags::empty().bits());
    b.put_u32_le(server_id);
    b.put(file);

    self.write_command(Command::COM_BINLOG_DUMP, &b[..]).await?;

    Ok(())
  }
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

/// Owned results for 0..N rows.
pub struct QueryResults {
  columns: Arc<Vec<Column>>,
  rows: Vec<Row>,
}

impl QueryResults {
  /// Consumes self and return only the first result.
  pub fn pop(mut self) -> Option<QueryResult> {
    self.rows.pop().map(|row| QueryResult {
      columns: self.columns.clone(),
      row,
    })
  }

  /// Returns a reference to the first result.
  pub fn first(&self) -> Option<QueryResultRef<'_>> {
    self.rows.first().map(|row| QueryResultRef {
      columns: self.columns.clone(),
      row,
    })
  }
}

impl Default for QueryResults {
  fn default() -> Self {
    let columns = Arc::new(Vec::new());
    let rows = Vec::new();
    Self { columns, rows }
  }
}

/// Owned result for a single row.
pub struct QueryResult {
  columns: Arc<Vec<Column>>,
  row: Row,
}

impl QueryResult {
  pub fn values(&self) -> &[Value] {
    self.row.values()
  }
}

/// Reference to a single row.
pub struct QueryResultRef<'a> {
  columns: Arc<Vec<Column>>,
  row: &'a Row,
}

// pub struct Field {
//   column: Column,
//   value: Value,
// }

// impl Field {
//   fn as_str(&self) -> Option<&str> {
//     // match self.value {
//     //   Value::Bytes(ref bytes) if self.column.column_type() => { None },
//     //   _ => None,
//     // }
//     todo!()
//   }

//   fn as_u8(&self) -> Option<u8> {
//     todo!()
//   }
//   fn as_u16(&self) -> Option<u16> {
//     todo!()
//   }
//   fn as_u32(&self) -> Option<u32> {
//     todo!()
//   }
//   fn as_u64(&self) -> Option<u64> {
//     todo!()
//   }
//   fn as_i8(&self) -> Option<i8> {
//     todo!()
//   }
//   fn as_i16(&self) -> Option<i16> {
//     todo!()
//   }
//   fn as_i32(&self) -> Option<i32> {
//     todo!()
//   }
//   fn as_i64(&self) -> Option<i64> {
//     todo!()
//   }
//   fn as_f32(&self) -> Option<f32> {
//     todo!()
//   }
//   fn as_f64(&self) -> Option<f64> {
//     todo!()
//   }

//   fn is_u8(&self) -> bool {
//     self.as_u8().is_some()
//   }
//   fn is_u16(&self) -> bool {
//     self.as_u16().is_some()
//   }
//   fn is_u32(&self) -> bool {
//     self.as_u32().is_some()
//   }
//   fn is_u64(&self) -> bool {
//     self.as_u64().is_some()
//   }
//   fn is_i8(&self) -> bool {
//     self.as_i8().is_some()
//   }
//   fn is_i16(&self) -> bool {
//     self.as_i16().is_some()
//   }
//   fn is_i32(&self) -> bool {
//     self.as_i32().is_some()
//   }
//   fn is_i64(&self) -> bool {
//     self.as_i64().is_some()
//   }
//   fn is_f32(&self) -> bool {
//     self.as_f32().is_some()
//   }
//   fn is_f64(&self) -> bool {
//     self.as_f64().is_some()
//   }

//   // TODO add other safe type conversions
// }

// https://mariadb.com/kb/en/connection/#sslrequest-packet

#[derive(Debug)]
pub struct BinlogEvent;
