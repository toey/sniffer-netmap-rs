#![allow(dead_code)]

mod blacklist;
mod bypass;
mod config;
mod hijack;
mod logger;
mod netmap;
mod packet;

use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use blacklist::{Action, Blacklist};
use bypass::BypassList;
use config::Config;
use logger::BlockLogger;
use netmap::NetmapDescriptor;

fn print_banner() {
    println!("==================================================================================");
    println!("==================================================================================");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg = match Config::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    print_banner();

    // Load blacklist and bypass list
    let blacklist = Blacklist::load("data/domain.idx", "data/domain.blk");
    let bypass = BypassList::load("data/bypass.txt");
    println!("==================================================================================");

    // Create shared state
    let blacklist = Arc::new(RwLock::new(blacklist));
    let bypass = Arc::new(bypass);
    let block_logger = Arc::new(
        BlockLogger::new("logs/block.log").unwrap_or_else(|e| {
            eprintln!("Failed to open block.log: {}", e);
            std::process::exit(1);
        }),
    );
    let version = Arc::new(cfg.version.clone());

    // Create raw socket for hijacking
    let raw_sock = match hijack::create_raw_socket() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket: {}", e);
            eprintln!("(Are you running as root?)");
            std::process::exit(1);
        }
    };

    println!("Capture:\t\t\t\t\t\t[ {} ]", cfg.interface);
    println!("Logging\t\t\t\t\t\t\t[ block.log ]");
    println!("Status\t\t\t\t\t\t\t[ Running ]");
    println!("==================================================================================");

    // Spawn blacklist reload thread (every 300 seconds)
    {
        let bl = Arc::clone(&blacklist);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(300));
            match std::panic::catch_unwind(|| {
                Blacklist::load("data/domain.idx", "data/domain.blk")
            }) {
                Ok(new_bl) => {
                    if let Ok(mut guard) = bl.write() {
                        *guard = new_bl;
                    }
                }
                Err(_) => {
                    eprintln!("can't reload list.");
                }
            }
        });
    }

    // Open netmap interface
    let netmap_ifname = format!("netmap:{}", cfg.interface);
    let parent_desc = match NetmapDescriptor::open(&netmap_ifname, None) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Can't open netmap device {}: {}", netmap_ifname, e);
            std::process::exit(1);
        }
    };

    let num_cpus = num_cpus();
    println!("We have {} cpus", num_cpus);
    println!(
        "Mapped {}KB memory at {:?}",
        parent_desc.memsize() >> 10,
        parent_desc.mem()
    );
    println!(
        "We have {} tx and {} rx rings",
        parent_desc.tx_rings(),
        parent_desc.rx_rings()
    );

    // Wait for NIC reset
    println!("Wait 2 seconds for NIC reset");
    thread::sleep(Duration::from_secs(2));

    // Spawn one thread per CPU/ring
    let mut handles = Vec::new();
    for i in 0..num_cpus {
        let ring_desc = match NetmapDescriptor::open_ring(&netmap_ifname, i as u16, &parent_desc) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Can't open netmap ring {}: {}", i, e);
                std::process::exit(1);
            }
        };

        println!(
            "My first ring is {} and last ring id is {} I'm thread {}",
            ring_desc.first_rx_ring(),
            ring_desc.last_rx_ring(),
            i
        );

        let bl = Arc::clone(&blacklist);
        let bp = Arc::clone(&bypass);
        let lg = Arc::clone(&block_logger);
        let ver = Arc::clone(&version);
        let mpls = cfg.mpls_enabled;

        let handle = thread::spawn(move || {
            netmap_thread(ring_desc, i, bl, bp, lg, raw_sock, ver, mpls);
        });
        handles.push(handle);
        println!("Start new thread {}", i);
    }

    println!("Wait for thread finish");
    for h in handles {
        let _ = h.join();
    }
}

/// Per-ring netmap receive thread.
fn netmap_thread(
    desc: NetmapDescriptor,
    thread_id: usize,
    blacklist: Arc<RwLock<Blacklist>>,
    bypass: Arc<BypassList>,
    logger: Arc<BlockLogger>,
    raw_sock: i32,
    version: Arc<String>,
    mpls_enabled: bool,
) {
    println!(
        "Reading from fd {} thread id: {}",
        desc.fd(),
        thread_id
    );

    loop {
        let poll_result = netmap::poll_fd(desc.fd(), -1);
        if poll_result == 0 {
            continue;
        }
        if poll_result < 0 {
            eprintln!("poll failed with return code -1");
            continue;
        }

        let nifp = desc.nifp();
        for ring_idx in desc.first_rx_ring()..=desc.last_rx_ring() {
            let rxring = unsafe { netmap_sys::netmap_rxring(nifp, ring_idx as u32) };
            if unsafe { netmap_sys::nm_ring_empty(rxring) } {
                continue;
            }

            netmap::receive_packets(rxring, |buf| {
                if packet::filter_packet(buf) {
                    handle_ip(
                        buf,
                        &blacklist,
                        &bypass,
                        &logger,
                        raw_sock,
                        &version,
                        mpls_enabled,
                    );
                }
            });
        }
    }
}

/// Process an IP packet: parse HTTP, check blacklist, hijack if needed.
/// Equivalent to the original `handle_IP()` function.
fn handle_ip(
    buf: &[u8],
    blacklist: &Arc<RwLock<Blacklist>>,
    bypass: &Arc<BypassList>,
    logger: &Arc<BlockLogger>,
    raw_sock: i32,
    version: &str,
    mpls_enabled: bool,
) {
    let pkt = match packet::parse_packet(buf, mpls_enabled) {
        Some(p) => p,
        None => return,
    };

    // Bypass check
    if !bypass.is_empty() && bypass.is_bypassed(pkt.ip.src) {
        return;
    }

    // Extract HTTP hostname
    let hostname = match packet::get_hostname(pkt.payload) {
        Some(h) => h,
        None => return,
    };

    if hostname.len() < 4 {
        return;
    }

    // Look up in blacklist
    let bl = match blacklist.read() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let entry = match bl.find_domain(&hostname) {
        Some(e) => e.clone(),
        None => return,
    };

    let src_ip = pkt.ip.src;
    let dst_ip = pkt.ip.dst;
    let src_port = pkt.tcp.src_port;
    let seq = pkt.tcp.seq;
    let ack = pkt.tcp.ack;
    let payload_len = pkt.payload.len() as u32;

    let mut is_domain = false;
    let mut monitor_only = false;

    let redirect_url = bl
        .get_redirect(&hostname)
        .cloned()
        .unwrap_or_default();

    match entry.action {
        Action::Block => {
            // index "0:0" → domain block
            is_domain = true;
            hijack::hijack_session(
                raw_sock, src_ip, dst_ip, src_port, 80, seq, ack, payload_len,
                &redirect_url, version,
            );
        }
        Action::MonitorDomain => {
            // index "2:2" → monitor only
            is_domain = true;
        }
        Action::MonitorUrl => {
            // index "3:3" → URL-level monitor
            monitor_only = true;
        }
    }

    // Extract request URI and build full URI
    let req_uri = packet::get_request_uri(pkt.payload).unwrap_or_default();
    let mut full_uri = format!("{}{}", hostname, req_uri);
    full_uri = full_uri.replace('\n', "").replace('\r', "");
    let full_uri = full_uri.trim().to_lowercase();

    // Check URL-level match
    if is_domain || bl.find_url(&full_uri) {
        if !is_domain && !monitor_only {
            hijack::hijack_session(
                raw_sock, src_ip, dst_ip, src_port, 80, seq, ack, payload_len,
                &redirect_url, version,
            );
        }

        // Log the blocked/monitored request
        let datetime = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        logger.log(&datetime, &src_ip.to_string(), src_port, &dst_ip.to_string(), &full_uri);
    }
}

/// Get the number of online CPUs.
fn num_cpus() -> usize {
    unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize }
}
