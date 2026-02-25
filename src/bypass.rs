use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

/// A list of IP/CIDR entries that should bypass filtering.
pub struct BypassList {
    entries: Vec<(Ipv4Addr, u8)>,
}

impl BypassList {
    /// Load bypass IPs from a file. Each line: "IP/CIDR" (e.g., "10.0.0.0/8").
    pub fn load(path: &str) -> Self {
        let mut entries = Vec::new();
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return BypassList { entries },
        };

        for line in BufReader::new(file).lines().flatten() {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('/').collect();
            if parts.len() == 2 {
                if let (Ok(ip), Ok(cidr)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<u8>())
                {
                    println!("Bypass IP :\t{}/{}", ip, cidr);
                    entries.push((ip, cidr));
                }
            }
        }
        BypassList { entries }
    }

    /// Check if an IP address matches any bypass entry (CIDR match).
    pub fn is_bypassed(&self, addr: Ipv4Addr) -> bool {
        for &(net, bits) in &self.entries {
            if cidr_match(addr, net, bits) {
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// CIDR match: check if addr is in the network net/bits.
fn cidr_match(addr: Ipv4Addr, net: Ipv4Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    if bits > 32 {
        return false;
    }
    let mask = if bits == 32 {
        0xFFFF_FFFFu32
    } else {
        0xFFFF_FFFFu32 << (32 - bits)
    };
    let addr_u32 = u32::from(addr);
    let net_u32 = u32::from(net);
    (addr_u32 & mask) == (net_u32 & mask)
}
