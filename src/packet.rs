use std::net::Ipv4Addr;

pub const ETHER_HDRLEN: usize = 14;
pub const MPLS_HDRLEN: usize = 4;

// TCP flags
pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_PUSH: u8 = 0x08;
pub const TH_ACK: u8 = 0x10;

/// Parsed IPv4 header (zero-copy from packet buffer).
#[derive(Debug)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub total_len: u16,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl IpHeader {
    /// Parse IP header from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let vhl = data[0];
        let version = vhl >> 4;
        let ihl = vhl & 0x0f;
        if version != 4 || ihl < 5 {
            return None;
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]);
        let protocol = data[9];
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        Some(IpHeader {
            version,
            ihl,
            total_len,
            protocol,
            src,
            dst,
        })
    }

    /// IP header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

/// Parsed TCP header.
#[derive(Debug)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: u8,
}

impl TcpHeader {
    /// Parse TCP header from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] & 0xf0) >> 4;
        let flags = data[13];
        Some(TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
        })
    }

    /// TCP header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }
}

/// Filter packet: return true if it's a TCP packet destined to port 80.
/// Checks both MPLS-encapsulated and non-MPLS packets.
pub fn filter_packet(buf: &[u8]) -> bool {
    // Try MPLS first (4 bytes after Ethernet header)
    if buf.len() > ETHER_HDRLEN + MPLS_HDRLEN + 40 {
        let ip_start = ETHER_HDRLEN + MPLS_HDRLEN;
        if let Some(ip) = IpHeader::parse(&buf[ip_start..]) {
            if ip.protocol == 6 {
                // TCP
                let tcp_start = ip_start + ip.header_len();
                if let Some(tcp) = TcpHeader::parse(&buf[tcp_start..]) {
                    if tcp.dst_port == 80 {
                        return true;
                    }
                }
            }
        }
    }

    // Try non-MPLS
    if buf.len() > ETHER_HDRLEN + 40 {
        let ip_start = ETHER_HDRLEN;
        if let Some(ip) = IpHeader::parse(&buf[ip_start..]) {
            if ip.protocol == 6 {
                let tcp_start = ip_start + ip.header_len();
                if let Some(tcp) = TcpHeader::parse(&buf[tcp_start..]) {
                    if tcp.dst_port == 80 {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Full packet parse: extract IP, TCP, and HTTP payload.
/// Returns (ip_header, tcp_header, payload_slice, mpls_offset) or None.
pub fn parse_packet(buf: &[u8], mpls_enabled: bool) -> Option<PacketInfo<'_>> {
    let mpls_offset = if mpls_enabled { MPLS_HDRLEN } else { 0 };

    // Try MPLS first
    let ip_start = ETHER_HDRLEN + mpls_offset;
    let mut ip = IpHeader::parse(buf.get(ip_start..)?)?;

    // If not TCP with MPLS, try without
    if ip.protocol != 6 {
        let ip_start_no_mpls = ETHER_HDRLEN;
        ip = IpHeader::parse(buf.get(ip_start_no_mpls..)?)?;
        if ip.protocol != 6 {
            return None;
        }
        // Non-MPLS path
        let tcp_start = ip_start_no_mpls + ip.header_len();
        let tcp = TcpHeader::parse(buf.get(tcp_start..)?)?;
        let payload_start = tcp_start + tcp.header_len();
        let payload_len =
            ip.total_len as usize - ip.header_len() - tcp.header_len();
        let payload = buf.get(payload_start..payload_start + payload_len)?;
        return Some(PacketInfo {
            ip,
            tcp,
            payload,
            mpls_offset: 0,
        });
    }

    let tcp_start = ip_start + ip.header_len();
    let tcp = TcpHeader::parse(buf.get(tcp_start..)?)?;
    let payload_start = tcp_start + tcp.header_len();
    let payload_len = ip.total_len as usize - ip.header_len() - tcp.header_len();
    let payload_end = payload_start + payload_len;
    let payload = buf.get(payload_start..payload_end.min(buf.len()))?;

    Some(PacketInfo {
        ip,
        tcp,
        payload,
        mpls_offset,
    })
}

/// Parsed packet info with references into the original buffer.
pub struct PacketInfo<'a> {
    pub ip: IpHeader,
    pub tcp: TcpHeader,
    pub payload: &'a [u8],
    pub mpls_offset: usize,
}

/// Extract the "Host: " value from an HTTP request payload.
pub fn get_hostname(payload: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(payload).ok()?;

    // Must contain \r\n (HTTP headers)
    if !s.contains("\r\n") {
        return None;
    }

    // Must contain "text/html" in Accept header (matching original filter)
    if !s.contains("text/html") {
        return None;
    }

    // Find "Host: " header
    let host_pos = s.find("Host: ")?;
    let after_host = &s[host_pos + 6..];
    let end_pos = after_host.find('\r')?;
    let mut hostname = after_host[..end_pos].trim().to_string();

    // Clean up hostname
    hostname = hostname.replace("http://", "");
    hostname = hostname.replace('/', "");
    hostname = hostname.replace(":80", "");

    // Strip "www." prefix
    if hostname.starts_with("www.") {
        hostname = hostname[4..].to_string();
    }

    if hostname.len() < 4 {
        return None;
    }

    Some(hostname)
}

/// Extract the request URI from an HTTP GET request payload.
pub fn get_request_uri(payload: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(payload).ok()?;
    let get_pos = s.find("GET /")?;
    let after_get = &s[get_pos..];
    let http_pos = after_get.find(" HTTP")?;
    let uri = &after_get[4..http_pos];
    Some(uri.trim().to_string())
}
