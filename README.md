# Httpsniffer
通过对网卡抓包来统计某一个端口的 HTTP 请求数据，然后将统计的数据发送到 statsd。

# Install

## Install Dependencies

Ubuntu:

```
apt-get install libpcap-dev
```

## Build
```
cargo build --release
```

## Binary Location
```
target/release/httpsniffer
```

# Usage

```
httpsniffer 0.1.0
gfreezy <gfreezy@gmail.com>

USAGE:
    httpsniffer [FLAGS] [OPTIONS] [device]

FLAGS:
    -h, --help       Prints help information
    -p, --promisc    Set device to promisc
    -V, --version    Prints version information
    -v, --verbose    Show more packets (maximum: 4)

OPTIONS:
    -n, --cpus <cpus>                      Number of cores
    -d, --duration <duration>              duration seconds [default: 10]
        --port <port>
        --statsd_host <statsd_host>        192.168.1.1:2221
        --statsd_prefix <statsd_prefix>

ARGS:
    <device>    Device for sniffing
```

Examples
```
httpsniffer --port 80 --duration 10 --statsd_host 192.168.1.1:9999 --statsd_prefix nginx eth0
```

# Statsd metrics
```
$prefix.$host.reqs_per_${duration}s|c
$prefix.$host.ips_per_${duration}s|c
$prefix.$host.pdids_per_${duration}s|c
```

```
xlb.01.deployer-x_xiachufang_com.reqs_per_10s:1|c
xlb.01.api-hermes_xiachufang_com.reqs_per_10s:32|c
xlb.01.jumpapp_xiachufang_com.ips_per_10s:21|c
xlb.01.m_xiachufang_com.ips_per_10s:133|c
xlb.01.lanfanapp_com.ips_per_10s:23|c
xlb.01.api-hermes_xiachufang_com.pdids_per_10s:30|c
xlb.01.cloudimgsrv_xiachufang_com.pdids_per_10s:2|c
```

# Bors commands
Syntax | Description
-------|------------
bors r+ | Run the test suite
bors r=\[list\] | Same as r+, but the "reviewer" will come from the argument
bors r- | Cancel an r+ or r=
bors try | Run the test suite without pushing
bors delegate+ | Allow the pull request author to r+
bors delegate=\[list\] | Allow the listed users to r+
bors ping | Will respond if bors is set up
