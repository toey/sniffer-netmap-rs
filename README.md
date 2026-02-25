# sniffer-netmap-rs

High-performance HTTP traffic monitor using **netmap** kernel-bypass packet capture, written in Rust.

Captures packets at line-rate via netmap's zero-copy ring buffers, extracts HTTP hostnames/URLs, matches against a configurable blacklist, and logs matched requests.

## Architecture

```
                         ┌─────────────────────────┐
                         │        main.rs           │
                         │  CLI parse, init, spawn  │
                         └────────────┬────────────┘
                                      │
              ┌───────────────────────┬┴┬───────────────────────┐
              │                       │ │                       │
     ┌────────▼────────┐    ┌────────▼─▼───────┐    ┌─────────▼────────┐
     │  Thread 0       │    │  Thread 1        │    │  Thread N        │
     │  RX Ring 0      │    │  RX Ring 1       │    │  RX Ring N       │
     │  netmap_thread() │    │  netmap_thread() │    │  netmap_thread() │
     └────────┬────────┘    └────────┬─────────┘    └─────────┬────────┘
              │                      │                        │
              └──────────────────────┼────────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   handle_ip()       │
                          │                     │
                          │  1. parse_packet()  │
                          │  2. bypass check    │
                          │  3. get_hostname()  │
                          │  4. blacklist match │
                          │  5. logger.log()    │
                          └─────────────────────┘
```

- One thread per CPU core, each bound to a netmap RX ring
- Shared blacklist reloaded every 300 seconds in background
- Thread-safe logging via `Mutex<BufWriter<File>>`

## Modules

| File | Description |
|---|---|
| `main.rs` | Entry point, thread spawning, packet dispatch |
| `netmap.rs` | Safe wrapper around netmap FFI (`nm_open`, `nm_close`, ring iteration) |
| `packet.rs` | Zero-copy parsing: Ethernet → IP → TCP → HTTP, hostname/URI extraction |
| `blacklist.rs` | Domain/URL lookup via `HashMap` + `HashSet` (O(1)), loads `.idx`/`.blk` files |
| `bypass.rs` | CIDR-based IP bypass list |
| `config.rs` | CLI argument parsing |
| `logger.rs` | Thread-safe CSV logger for matched requests |

## Requirements

- Linux with **netmap** kernel module loaded
- Root privileges (netmap device access)
- Rust 1.56+ (edition 2021)
- `netmap-sys` crate (workspace sibling)

## Build

```bash
cargo build --release
```

## Usage

```bash
sudo ./target/release/sniffer <interface>
```

Example:

```bash
sudo ./sniffer ens1f0
```

## Data Files

| File | Format | Description |
|---|---|---|
| `data/domain.idx` | `domain:start:end:redirect_url` | Domain watchlist with action codes |
| `data/domain.blk` | One URL per line | Full URL watchlist |
| `data/bypass.txt` | `IP/CIDR` per line | Source IPs to skip (e.g. `10.0.0.0/8`) |

### Action Codes (domain.idx)

| Index | Action |
|---|---|
| `0:0` | Monitor domain |
| `2:2` | Monitor domain |
| `3:3` | Monitor URL-level |

## Log Output

Logged to `logs/block.log`:

```
2025-01-15 10:30:45,192.168.1.100,54321:93.184.216.34,93.184.216.34:80,http://example.com/page
```

## License

MIT
