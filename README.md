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
$prefix.reqs_per_${duration}s|c#$tag_key1:$tag_value1,$tag_key2:$tag_value2
$prefix.ips_per_${duration}s|c#$tag_key1:$tag_value1,$tag_key2:$tag_value2
$prefix.pdids_per_${duration}s|c#$tag_key1:$tag_value1,$tag_key2:$tag_value2
```

```
nginx.xlb-01.ips_per_10s:4698|c|#host:api_xiachufang_com
nginx.xlb-01.pdids_per_10s:4112|c|#host:api_xiachufang_com
nginx.xlb-01.reqs_per_10s:10062|c|#host:api_xiachufang_com
nginx.xlb-01.reqs_per_10s:10122|c|#host:api_xiachufang_com
nginx.xlb-01.ips_per_10s:4737|c|#host:api_xiachufang_com
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
