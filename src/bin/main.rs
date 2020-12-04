use futures::future::FutureExt;
use futures::select;
use futures::stream::StreamExt;
use tail_mysql::conn::{Connection, ReplicationOptions};
use tokio::sync::oneshot::{self, Receiver as OneshotReceiver};
use url::Url;

#[tokio::main]
async fn main() {
  let matches = clap::App::new("tail_mysql")
    .version("1.0")
    .author("maxime.bedard@shopify.com")
    .about(
      "tail_mysql is a utility to stream MYSQL binlog, transform it and push onto another Sink.",
    )
    .arg(
      clap::Arg::with_name("config")
        .short("c")
        .long("config")
        .value_name("FILE")
        .help("Sets a custom config file")
        .takes_value(true),
    )
    .arg(
      clap::Arg::with_name("url")
        .short("u")
        .long("url")
        .help("MYSQL url")
        .takes_value(true),
    )
    .get_matches();

  let raw_mysql_url = matches
    .value_of("url")
    .unwrap_or("mysql://root:password@127.0.0.1:3306");
  let mysql_url = Url::parse(raw_mysql_url).unwrap_or_else(|err| {
    eprintln!("Failed to parse mysql URL: {}", err);
    std::process::exit(1);
  });

  let (gracefully_close_streamer_sender, gracefully_close_streamer_receiver) =
    oneshot::channel::<()>();

  let streamer_handle = tokio::task::spawn(streamer(mysql_url, gracefully_close_streamer_receiver));

  select! {
    _ = tokio::signal::ctrl_c().fuse() => {
      let _ = gracefully_close_streamer_sender.send(());
    },
    _ = streamer_handle.fuse() => {},
  }
}

async fn streamer(mysql_url: Url, _gracefully_close: OneshotReceiver<()>) {
  let mut conn = Connection::connect(mysql_url).await.unwrap();
  println!("sending ping");
  if conn.ping().await.is_ok() {
    println!("received pong");
  }

  println!("sending version query");
  let _results = conn.query("SELECT VERSION();").await.unwrap();

  let stream = conn
    .binlog_stream(ReplicationOptions::default())
    .await
    .unwrap();

  futures::pin_mut!(stream);

  while let Some(evt) = stream.next().await {
    println!("{:?}", evt);
  }
}
