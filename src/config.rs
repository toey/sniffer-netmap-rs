/// Runtime configuration parsed from CLI arguments.
pub struct Config {
    /// Network interface for netmap capture (e.g., "ens1f0")
    pub interface: String,
    /// Outgoing interface for sending hijack packets (e.g., "enp3s0f0")
    pub out_interface: String,
    /// Source MAC address (e.g., "0c:c4:7a:da:5c:28")
    pub src_mac: [u8; 6],
    /// Gateway/destination MAC address
    pub dst_mac: [u8; 6],
    /// Version string appended to redirect URL
    pub version: String,
    /// Whether to handle MPLS-encapsulated packets
    pub mpls_enabled: bool,
}

impl Config {
    /// Parse from command line arguments.
    /// Usage: sniffer <interface> <out_interface> <src_mac> <dst_mac> <version>
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        if args.len() < 6 {
            return Err(format!(
                "Usage: {} <interface> <out_interface> <src_mac> <dst_mac> <version>",
                args.first().map(|s| s.as_str()).unwrap_or("sniffer")
            ));
        }

        let src_mac = parse_mac(&args[3])?;
        let dst_mac = parse_mac(&args[4])?;

        Ok(Config {
            interface: args[1].clone(),
            out_interface: args[2].clone(),
            src_mac,
            dst_mac,
            version: args[5].clone(),
            mpls_enabled: true,
        })
    }
}

/// Parse a MAC address string like "0c:c4:7a:da:5c:28" into bytes.
fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("Invalid MAC address: {}", s));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("Invalid MAC byte: {}", part))?;
    }
    Ok(mac)
}
