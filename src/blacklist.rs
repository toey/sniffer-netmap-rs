use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Action to take on a matched domain/URL.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Monitor — domain level (index "0:0" or "2:2")
    MonitorDomain,
    /// Monitor — URL level (index "3:3")
    MonitorUrl,
}

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub index: String,
    pub action: Action,
}

/// Blacklist holding domain and URL lookup tables.
/// Replaces the original AVL tree + vector approach with HashMaps for O(1) lookup.
pub struct Blacklist {
    /// hostname → DomainEntry
    domains: HashMap<String, DomainEntry>,
    /// full URL set (hostname + path)
    urls: HashSet<String>,
}

impl Blacklist {
    pub fn new() -> Self {
        Blacklist {
            domains: HashMap::new(),
            urls: HashSet::new(),
        }
    }

    /// Load blacklist from domain.idx and domain.blk files.
    ///
    /// domain.idx format: `<domain>:<start>:<end>:<redirect_url>`
    /// domain.blk format: one full URL per line
    pub fn load(idx_path: &str, blk_path: &str) -> Self {
        let mut bl = Blacklist::new();

        // Load domain index
        if let Ok(file) = File::open(idx_path) {
            let mut count = 0;
            for line in BufReader::new(file).lines().flatten() {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 4 {
                    continue;
                }

                let domain = parts[0]
                    .trim()
                    .replace('\n', "")
                    .replace('\r', "")
                    .replace(' ', "");

                let index = format!("{}:{}", parts[1], parts[2]);

                let action = match index.as_str() {
                    "3:3" => Action::MonitorUrl,
                    _ => Action::MonitorDomain,
                };

                // Only insert if not already present (matches original behavior)
                if !bl.domains.contains_key(&domain) {
                    bl.domains.insert(
                        domain.clone(),
                        DomainEntry { index, action },
                    );
                }

                count += 1;
            }

            // Load URL block list
            let mut count2 = 0;
            if let Ok(file) = File::open(blk_path) {
                for line in BufReader::new(file).lines().flatten() {
                    let url = line
                        .trim()
                        .replace('\n', "")
                        .replace('\r', "");
                    if !url.is_empty() {
                        bl.urls.insert(url);
                        count2 += 1;
                    }
                }
            }

            println!("Reload List Domain: {}/{} URLs", count, count2);
        } else {
            eprintln!("Can't open blacklist file: {}", idx_path);
        }

        bl
    }

    /// Look up a hostname in the domain table.
    /// Returns None if the hostname is not in the blacklist.
    pub fn find_domain(&self, hostname: &str) -> Option<&DomainEntry> {
        self.domains.get(hostname)
    }

    /// Check if a full URL is in the URL block list.
    pub fn find_url(&self, full_url: &str) -> bool {
        self.urls.contains(full_url)
    }
}
