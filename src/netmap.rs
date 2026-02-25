use netmap_sys::*;
use std::ptr;

/// Safe wrapper around a netmap descriptor.
pub struct NetmapDescriptor {
    inner: *mut nm_desc,
}

// Safety: nm_desc is accessed only from the owning thread or
// through per-ring child descriptors.
unsafe impl Send for NetmapDescriptor {}

impl NetmapDescriptor {
    /// Open a netmap port (e.g., "netmap:eth0").
    pub fn open(ifname: &str, req: Option<&nmreq>) -> Result<Self, String> {
        let d = unsafe { nm_open(ifname, req, 0, ptr::null()) };
        if d.is_null() {
            return Err(format!("Failed to open netmap device: {}", ifname));
        }
        Ok(NetmapDescriptor { inner: d })
    }

    /// Open a child descriptor for a specific ring (used for multi-threaded access).
    pub fn open_ring(
        ifname: &str,
        ring_id: u16,
        parent: &NetmapDescriptor,
    ) -> Result<Self, String> {
        unsafe {
            // Copy the parent descriptor (like C: `struct nm_desc nmd = *netmap_descriptor;`)
            let mut nmd: nm_desc = ptr::read(parent.inner);
            nmd.self_ = &mut nmd as *mut nm_desc;

            nmd.req.nr_flags = NR_REG_ONE_NIC;
            nmd.req.nr_ringid = ring_id;

            let flags = NM_OPEN_NO_MMAP | NM_OPEN_IFNAME | (NETMAP_NO_TX_POLL as u64);

            let d = nm_open(ifname, None, flags, &nmd as *const nm_desc);
            if d.is_null() {
                return Err(format!(
                    "Failed to open netmap ring {} for {}",
                    ring_id, ifname
                ));
            }
            // Prevent nmd from being dropped (it was a stack copy, not an allocation)
            std::mem::forget(nmd);
            Ok(NetmapDescriptor { inner: d })
        }
    }

    /// Get the file descriptor for poll().
    pub fn fd(&self) -> i32 {
        unsafe { (*self.inner).fd }
    }

    /// Get the netmap interface pointer.
    pub fn nifp(&self) -> *mut netmap_if {
        unsafe { (*self.inner).nifp }
    }

    /// Number of TX rings.
    pub fn tx_rings(&self) -> u16 {
        unsafe { (*self.inner).req.nr_tx_rings }
    }

    /// Number of RX rings.
    pub fn rx_rings(&self) -> u16 {
        unsafe { (*self.inner).req.nr_rx_rings }
    }

    /// Memory size mapped.
    pub fn memsize(&self) -> u32 {
        unsafe { (*self.inner).req.nr_memsize }
    }

    /// Memory pointer.
    pub fn mem(&self) -> *mut libc::c_void {
        unsafe { (*self.inner).mem }
    }

    /// First RX ring index.
    pub fn first_rx_ring(&self) -> u16 {
        unsafe { (*self.inner).first_rx_ring }
    }

    /// Last RX ring index.
    pub fn last_rx_ring(&self) -> u16 {
        unsafe { (*self.inner).last_rx_ring }
    }

    /// Get the raw inner pointer (for FFI operations).
    pub fn as_ptr(&self) -> *const nm_desc {
        self.inner
    }
}

impl Drop for NetmapDescriptor {
    fn drop(&mut self) {
        unsafe {
            nm_close(self.inner);
        }
    }
}

/// Process all available packets in a netmap RX ring.
/// Calls `handler` for each packet buffer.
pub fn receive_packets<F>(ring: *mut netmap_ring, mut handler: F) -> u32
where
    F: FnMut(&[u8]),
{
    unsafe {
        let mut cur = (*ring).cur;
        let n = nm_ring_space(ring);

        for _ in 0..n {
            let slot = ring_slot(ring, cur);
            let buf_ptr = netmap_buf(ring, (*slot).buf_idx);
            let len = (*slot).len as usize;
            let buf = std::slice::from_raw_parts(buf_ptr as *const u8, len);

            handler(buf);

            cur = nm_ring_next(ring, cur);
        }

        (*ring).head = cur;
        (*ring).cur = cur;
        n
    }
}

/// Poll a netmap file descriptor for incoming packets (blocking).
pub fn poll_fd(fd: i32, timeout_ms: i32) -> i32 {
    unsafe {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        libc::poll(&mut pfd, 1, timeout_ms)
    }
}
