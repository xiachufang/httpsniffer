use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use get_if_addrs::Interface;
use num_cpus;
use pcap::Capture;
use pcap::Device;
use pcap::Direction;
use structopt::clap::AppSettings;
use structopt::StructOpt;
use threadpool::ThreadPool;
use uuid::Uuid;

use sniffglue::centrifuge;
use sniffglue::link::DataLink;
use sniffglue::structs::ether::Ether;
use sniffglue::structs::http::Request;
use sniffglue::structs::ipv4::IPv4;
use sniffglue::structs::raw::Raw;
use sniffglue::structs::tcp::TCP;

mod metrics;

type Message = (Ipv4Addr, Request);
type Sender = mpsc::Sender<Message>;
type Receiver = mpsc::Receiver<Message>;

#[derive(Debug, StructOpt)]
#[structopt(raw(global_settings = "&[AppSettings::ColoredHelp]"))]
pub struct Args {
    #[structopt(long = "statsd_host", help = "192.168.1.1:2221")]
    pub statsd_host: Option<String>,
    #[structopt(long = "statsd_prefix")]
    pub statsd_prefix: Option<String>,
    #[structopt(
        short = "d",
        long = "duration",
        default_value = "10",
        help = "duration seconds"
    )]
    pub duration: u64,
    /// Set device to promisc
    #[structopt(short = "p", long = "promisc")]
    pub promisc: bool,
    #[structopt(long = "port")]
    pub port: Option<u16>,
    /// Show more packets (maximum: 4)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbose: u64,
    /// Number of cores
    #[structopt(short = "n", long = "cpus")]
    pub cpus: Option<usize>,
    /// Device for sniffing
    pub device: Option<String>,
}

fn get_if_addr(name: &str) -> Option<Ipv4Addr> {
    let addrs: Vec<Interface> = get_if_addrs::get_if_addrs().expect("get if addrs");
    addrs
        .iter()
        .find(|iface| iface.name == name)
        .and_then(|iface| match iface.ip() {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        })
}

fn parse_http_request(packet: Raw, port: u16, addr: Ipv4Addr) -> Option<Message> {
    match packet {
        Raw::Ether(_, ether) => match ether {
            Ether::IPv4(ipv4_header, ipv4) => {
                if ipv4_header.dest_addr != addr {
                    return None;
                }

                match ipv4 {
                    IPv4::TCP(tcp_header, tcp) => {
                        if port != 0 && tcp_header.dest_port != port {
                            return None;
                        }
                        match tcp {
                            TCP::HTTP(request) => Some((ipv4_header.source_addr, request)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn main() {
    env_logger::init();

    let args = dbg!(Args::from_args());

    let device = match args.device {
        Some(device) => device,
        None => Device::lookup().expect("lookup device").name,
    };

    let device_addr = get_if_addr(&device).expect("get device addr");
    let port = args.port.unwrap_or(0);
    let cpus = args.cpus.unwrap_or_else(num_cpus::get);
    let duration = args.duration;
    let statsd_prefix = args.statsd_prefix.unwrap_or_else(|| "".to_string());

    let mut cap = match Capture::from_device(device.as_str())
        .expect("from device")
        .promisc(args.promisc)
        .open()
    {
        Ok(cap) => {
            eprintln!("Listening on device: {:?}", device);
            cap
        }
        Err(e) => {
            eprintln!("Failed to open interface {:?}: {}", device, e);
            return;
        }
    };
    cap.direction(Direction::In).expect("set capture direction");
    cap.filter(&format!("tcp dst port {}", port))
        .expect("set capture filter");

    let (tx, rx): (Sender, Receiver) = mpsc::channel();

    let join = thread::spawn(move || {
        let pool = ThreadPool::new(cpus);

        let datalink = match DataLink::from_linktype(cap.get_datalink()) {
            Ok(link) => link,
            Err(x) => {
                // TODO: properly exit the program
                eprintln!(
                    "Unknown link type: {:?}, {:?}, {}",
                    x.get_name().unwrap_or_else(|_| "???".into()),
                    x.get_description().unwrap_or_else(|_| "???".into()),
                    x.0
                );
                return;
            }
        };

        loop {
            match cap.next() {
                Ok(packet) => {
                    let tx = tx.clone();
                    let packet = packet.data.to_vec();

                    let datalink = datalink.clone();
                    pool.execute(move || {
                        let packet = centrifuge::parse(&datalink, &packet);
                        if let Some(message) = parse_http_request(packet, port, device_addr) {
                            tx.send(message).expect("send");
                        }
                    });
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    return;
                }
            }
        }
    });

    let registry = metrics::Registry::new(args.statsd_host, statsd_prefix);
    let registry2 = registry.clone();
    let t = thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(duration));
        registry2.send();
    });

    for (_addr, request) in rx.iter() {
        let real_ip = request.extra_headers.get("x-forwarded-for");
        let pdid = request.extra_headers.get("x-xcf-pdid");
        let host = if let Some(host) = request.host.as_ref() {
            host.replace(".", "_")
        } else {
            continue;
        };

        if let Some(Some(ip)) = real_ip {
            let unique_ips = registry.get_cardinality(
                format!("{}.ips_per_{}s", &host, duration),
                format!("ips_per_{}s", duration),
                {
                    let mut map = HashMap::new();
                    map.insert("host".to_string(), host.clone());
                    Some(map)
                },
            );
            unique_ips.add(ip.to_owned());
        }

        let reqs = registry.get_counter(
            format!("{}.reqs_per_{}s", &host, duration),
            format!("reqs_per_{}s", duration),
            {
                let mut map = HashMap::new();
                map.insert("host".to_string(), host.clone());
                Some(map)
            },
        );
        reqs.add(1);
        if args.verbose > 0 {
            println!("{:?}", &request);
        }

        if let Some(Some(pdid)) = pdid {
            let my_uuid = match Uuid::parse_str(&pdid.replace("-", "")) {
                Ok(uuid) => uuid,
                Err(_) => continue,
            };
            let unique_pdids = registry.get_cardinality(
                format!("{}.pdids_per_{}s", &host, duration),
                format!("pdids_per_{}s", duration),
                {
                    let mut map = HashMap::new();
                    map.insert("host".to_string(), host.clone());
                    Some(map)
                },
            );
            unique_pdids.add(my_uuid.to_string());
        }
    }

    t.join().expect("join timer");
    join.join().expect("join");
}
