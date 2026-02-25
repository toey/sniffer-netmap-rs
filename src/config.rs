/// Runtime configuration parsed from CLI arguments.
pub struct Config {
    /// Network interface for netmap capture (e.g., "ens1f0")
    pub interface: String,
    /// Whether to handle MPLS-encapsulated packets
    pub mpls_enabled: bool,
}

impl Config {
    /// Parse from command line arguments.
    /// Usage: sniffer <interface>
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        if args.len() < 2 {
            return Err(format!(
                "Usage: {} <interface>",
                args.first().map(|s| s.as_str()).unwrap_or("sniffer")
            ));
        }

        Ok(Config {
            interface: args[1].clone(),
            mpls_enabled: true,
        })
    }
}
