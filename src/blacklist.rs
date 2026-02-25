use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Action to take on a matched domain/URL.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Block and redirect (index "0:0")
    Block,
    /// Monitor only — domain level (index "2:2")
    MonitorDomain,
    /// Monitor only — URL level (index "3:3")
    MonitorUrl,
}

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub index: String,
    pub action: Action,
    pub redirect_url: String,
}

/// Blacklist holding domain and URL lookup tables.
/// Replaces the original AVL tree + vector approach with HashMaps for O(1) lookup.
pub struct Blacklist {
    /// hostname → DomainEntry
    domains: HashMap<String, DomainEntry>,
    /// full URL set (hostname + path)
    urls: HashSet<String>,
    /// hostname → redirect URL
    url_redirects: HashMap<String, String>,
}

/// Result of a blacklist lookup.
pub struct LookupResult {
    pub action: Action,
    pub is_domain: bool,
    pub redirect_url: String,
}

impl Blacklist {
    pub fn new() -> Self {
        Blacklist {
            domains: HashMap::new(),
            urls: HashSet::new(),
            url_redirects: HashMap::new(),
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
                let redirect_url = parts[3].to_string();

                let action = match index.as_str() {
                    "0:0" => Action::Block,
                    "2:2" => Action::MonitorDomain,
                    "3:3" => Action::MonitorUrl,
                    _ => Action::Block,
                };

                // Only insert if not already present (matches original behavior)
                if !bl.domains.contains_key(&domain) {
                    bl.domains.insert(
                        domain.clone(),
                        DomainEntry {
                            index,
                            action,
                            redirect_url: redirect_url.clone(),
                        },
                    );
                }

                bl.url_redirects
                    .entry(domain)
                    .or_insert(redirect_url);

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

    /// Get the redirect URL for a hostname.
    pub fn get_redirect(&self, hostname: &str) -> Option<&String> {
        self.url_redirects.get(hostname)
    }

    /// Full lookup: checks domain first, then URL.
    /// Returns the action to take, or None if not matched.
    pub fn lookup(&self, hostname: &str, full_uri: &str) -> Option<LookupResult> {
        // First check if hostname is in domain list at all
        let entry = self.find_domain(hostname)?;

        let redirect_url = entry.redirect_url.clone();

        match entry.action {
            Action::Block => {
                // Domain-level block — redirect immediately
                Some(LookupResult {
                    action: Action::Block,
                    is_domain: true,
                    redirect_url,
                })
            }
            Action::MonitorDomain => {
                // Domain-level monitor only — log but don't redirect
                Some(LookupResult {
                    action: Action::MonitorDomain,
                    is_domain: true,
                    redirect_url,
                })
            }
            Action::MonitorUrl => {
                // URL-level — check if the specific URL is blocked
                if self.find_url(full_uri) {
                    Some(LookupResult {
                        action: Action::MonitorUrl,
                        is_domain: false,
                        redirect_url,
                    })
                } else {
                    // Check URL match for blocking
                    if self.find_url(full_uri) {
                        Some(LookupResult {
                            action: Action::Block,
                            is_domain: false,
                            redirect_url,
                        })
                    } else {
                        None
                    }
                }
            }
        }
    }

    /// Comprehensive handle_ip-style lookup matching the original C++ logic:
    /// 1. Check hostname in domain table (return None if not found)
    /// 2. If "0:0" → domain block + hijack
    /// 3. If "2:2" → domain monitor (log only)
    /// 4. If "3:3" → URL monitor
    /// 5. Else check full_uri in URL hash → block + hijack
    pub fn check(
        &self,
        hostname: &str,
        full_uri: &str,
    ) -> Option<(Action, bool, bool, String)> {
        // (action, is_domain, should_hijack, redirect_url)
        let entry = self.find_domain(hostname)?;
        let redirect_url = self
            .get_redirect(hostname)
            .cloned()
            .unwrap_or_default();

        match entry.action {
            Action::Block => {
                // index "0:0" → domain block, hijack
                Some((Action::Block, true, true, redirect_url))
            }
            Action::MonitorDomain => {
                // index "2:2" → domain monitor, no hijack, but check URL too
                if self.find_url(full_uri) {
                    // URL in block list → log it
                    Some((Action::MonitorDomain, true, false, redirect_url))
                } else {
                    Some((Action::MonitorDomain, true, false, redirect_url))
                }
            }
            Action::MonitorUrl => {
                // index "3:3" → URL-level monitor
                if self.find_url(full_uri) {
                    // matched URL → log but don't hijack
                    Some((Action::MonitorUrl, false, false, redirect_url))
                } else if self.find_url(full_uri) {
                    Some((Action::Block, false, true, redirect_url))
                } else {
                    None
                }
            }
        }
    }
}
