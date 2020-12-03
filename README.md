# tail_mysql

tail_mysql is a utility to stream MYSQL binlog, filter, transform, and push the data through another Sink.

# Why

Wanted to get a bit more familiar with tokio, and decoding things are fun. And it could be useful if I want to do an online migration tool that need to copy commited data from mysql into things like Kafka, Noria, or even another MYSQL really.

# Supported

- [x] Simple text queries
- [x] MYSQL >= 5.7.5
- [ ] Binlog streaming (in progress)
- [ ] Map/reduce
- [ ] Custom sinks
- [ ] SSL
- [ ] Compression

# Todos

- make the parsing logic safer (e.g return unexpected EOF)
- potentially reduce copying of data in a whole lot of places during parsing
- add a lot of tests
- error handling is an absolute mess

# Testing

```sh
# starting a docker container to test against
docker run --detach --name=actw_mysql \
  --env="MYSQL_ROOT_PASSWORD=password" \
  --publish 3306:3306 mysql:5.7

cargo test
cargo run
```
