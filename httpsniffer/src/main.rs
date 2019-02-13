use pcap::Device;
use pcap::Capture;

use threadpool::ThreadPool;

use std::thread;
use std::sync::mpsc;

use sniffglue::centrifuge;
use sniffglue::link::DataLink;
use sniffglue::sandbox;
use sniffglue::structs;
use num_cpus;
use structopt::StructOpt;


type Message = structs::raw::Raw;
type Sender = mpsc::Sender<Message>;
type Receiver = mpsc::Receiver<Message>;

use structopt::clap::AppSettings;
use sniffglue::structs::raw::Raw;
use sniffglue::structs::ether::Ether;
use sniffglue::structs::ipv4::IPv4;
use sniffglue::structs::tcp::TCP;
use std::net::Ipv4Addr;
use get_if_addrs::Interface;
use std::net::IpAddr;

#[derive(Debug, StructOpt)]
#[structopt(raw(global_settings = "&[AppSettings::ColoredHelp]"))]
pub struct Args {
    /// Set device to promisc
    #[structopt(short="p", long="promisc")]
    pub promisc: bool,
    /// Detailed output
    #[structopt(short="d", long="detailed")]
    pub detailed: bool,
    /// Json output (unstable)
    #[structopt(short="j", long="json")]
    pub json: bool,
    /// Show more packets (maximum: 4)
    #[structopt(short="v", long="verbose",
    parse(from_occurrences))]
    pub verbose: u64,
    /// Open device as pcap file
    #[structopt(short="r", long="read")]
    pub read: bool,
    /// Number of cores
    #[structopt(short="n", long="cpus")]
    pub cpus: Option<usize>,
    /// Device for sniffing
    pub device: Option<String>,
}

// XXX: workaround, remove if possible
enum CapWrap {
    Active(Capture<pcap::Active>),
    Offline(Capture<pcap::Offline>),
}

impl CapWrap {
    fn activate(self) -> Capture<pcap::Activated> {
        match self {
            CapWrap::Active(cap) => cap.into(),
            CapWrap::Offline(cap) => cap.into(),
        }
    }
}

impl From<Capture<pcap::Active>> for CapWrap {
    fn from(cap: Capture<pcap::Active>) -> CapWrap {
        CapWrap::Active(cap)
    }
}

impl From<Capture<pcap::Offline>> for CapWrap {
    fn from(cap: Capture<pcap::Offline>) -> CapWrap {
        CapWrap::Offline(cap)
    }
}


fn get_if_addr(name: &str) -> Option<Ipv4Addr> {
    let addrs: Vec<Interface> = get_if_addrs::get_if_addrs().expect("get if addrs");
    addrs.iter().find(|iface| iface.name == name).and_then(|iface| {
        match iface.ip() {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        }
    })
}

fn main() {
    // this goes before the sandbox so logging is available
    env_logger::init();

    sandbox::activate_stage1().expect("init sandbox stage1");

    let args = Args::from_args();

    let device = match args.device {
        Some(device) => device,
        None => Device::lookup().unwrap().name,
    };

    let device_addr = get_if_addr(&device).expect("get device addr");

    let cpus = args.cpus.unwrap_or_else(num_cpus::get);
    let cap: CapWrap = if !args.read {
        match Capture::from_device(device.as_str()).unwrap()
            .promisc(args.promisc)
            .open() {
            Ok(cap) => {
                eprintln!("Listening on device: {:?}", device);
                cap.into()
            },
            Err(e) => {
                eprintln!("Failed to open interface {:?}: {}", device, e);
                return;
            },
        }
    } else {
        match Capture::from_file(device.as_str()) {
            Ok(cap) => {
                eprintln!("Reading from file: {:?}", device);
                cap.into()
            },
            Err(e) => {
                eprintln!("Failed to open pcap file {:?}: {}", device, e);
                return;
            },
        }
    };


    let (tx, rx): (Sender, Receiver) = mpsc::channel();

    sandbox::activate_stage2().expect("init sandbox stage2");

    let join = thread::spawn(move || {
        let pool = ThreadPool::new(cpus);

        let mut cap = cap.activate();

        let datalink = match DataLink::from_linktype(cap.get_datalink()) {
            Ok(link) => link,
            Err(x) => {
                // TODO: properly exit the program
                eprintln!("Unknown link type: {:?}, {:?}, {}",
                          x.get_name().unwrap_or_else(|_| "???".into()),
                          x.get_description().unwrap_or_else(|_| "???".into()),
                          x.0);
                return;
            },
        };

        while let Ok(packet) = cap.next() {
            // let ts = packet.header.ts;
            // let len = packet.header.len;

            let tx = tx.clone();
            let packet = packet.data.to_vec();

            let datalink = datalink.clone();
            pool.execute(move || {
                let packet = centrifuge::parse(&datalink, &packet);
                tx.send(packet).unwrap();
            });
        }
    });

    for packet in rx.iter() {
        match &packet {
            Raw::Ether(_, ether) => {
                match ether {
                    Ether::IPv4(ipv4_header, ipv4) => {

                        if ipv4_header.dest_addr != device_addr {
                            continue;
                        }

                        match ipv4 {
                            IPv4::TCP(tcp_header, tcp) => {
                                if tcp_header.dest_port != 80 {
                                    continue;
                                }

                                match tcp {
                                    TCP::HTTP(request) => {
                                        println!("{} {:?}", ipv4_header.source_addr, request);
                                    },
                                    _ => {},
                                }
                            },
                            IPv4::UDP(_, _) => {},
                            IPv4::Unknown(_) => {},
                        }
                    },
                    _ => {},
                }
            },
            _ => {}
        };
    }

    join.join().unwrap();
}
