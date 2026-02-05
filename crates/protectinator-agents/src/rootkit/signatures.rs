//! Known rootkit signatures and detection patterns

/// Known malicious kernel module names
pub const KNOWN_ROOTKIT_MODULES: &[(&str, &str)] = &[
    // Well-known rootkits
    ("diamorphine", "Diamorphine LKM rootkit"),
    ("reptile", "Reptile LKM rootkit"),
    ("azazel", "Azazel userland rootkit"),
    ("jynx", "Jynx/Jynx2 rootkit"),
    ("adore", "Adore LKM rootkit"),
    ("adore-ng", "Adore-NG LKM rootkit"),
    ("knark", "Knark LKM rootkit"),
    ("suckit", "SuckIT kernel rootkit"),
    ("modhide", "Module hiding rootkit"),
    ("rkh", "Generic rootkit hunter detection"),
    ("enyelkm", "Enye LKM rootkit"),
    ("phalanx", "Phalanx rootkit"),
    ("override", "Override rootkit"),
    ("rkit", "Generic rootkit module"),
    ("hacked", "Generic hacked module indicator"),
    ("backdoor", "Generic backdoor module indicator"),
    ("hide", "Generic hiding module"),
    ("stealth", "Generic stealth module"),
    ("rootkit", "Generic rootkit module"),
    ("suterusu", "Suterusu LKM rootkit"),
    ("bdvl", "BDVL userland rootkit"),
    ("beurk", "BEURK userland rootkit"),
    ("horsepill", "Horsepill bootkit"),
    ("nurupo", "Nurupo rootkit"),
    ("rkduck", "Rkduck rootkit"),
    ("rooty", "Rooty rootkit"),
    ("satan", "Satan rootkit"),
    ("keylogger", "Kernel keylogger module"),
    ("hid_keyboard", "Suspicious HID keyboard module"),
];

/// Known suspicious module name patterns (regex-like patterns)
pub const SUSPICIOUS_MODULE_PATTERNS: &[&str] = &[
    // Single-letter or very short random names
    "^[a-z]$",
    "^[a-z]{2}$",
    // Common obfuscation patterns
    "^\\.[a-z]+",      // Hidden module names starting with dot
    "^_[a-z]+_$",      // Underscored names
    "hideme",          // Obvious hiding intent
    "invisible",       // Obvious hiding intent
    "infected",        // Indicator of compromise
    "pwned",           // Indicator of compromise
    "shell",           // Shell-related
    "netfilter_hook",  // Suspicious netfilter hooks
    "^nf_[a-z]+_hack", // Netfilter hacks
];

/// Suspicious process names that may indicate rootkit activity
pub const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    // Known malware
    "xmrig",
    "minerd",
    "cpuminer",
    "cryptonight",
    "stratum",
    "nicehash",
    // Reverse shells
    "nc.traditional",
    "ncat",
    "socat",
    // Suspicious names
    ".tmp",
    "....",
    "     ",
    "[kworker/0:0]", // Fake kernel thread
    "[migration/0]", // Fake kernel thread (if in userspace)
];

/// Paths commonly used by rootkits for persistence
pub const ROOTKIT_PERSISTENCE_PATHS: &[&str] = &[
    "/etc/ld.so.preload",
    "/lib/security/.config",
    "/usr/lib/security/.config",
    "/dev/shm/.x",
    "/tmp/.X11-unix/.x",
    "/var/tmp/.x",
    "/root/.bashrc.d",
    "/etc/profile.d/.hidden",
];

/// LD_PRELOAD related suspicious paths
pub const SUSPICIOUS_PRELOAD_PATHS: &[&str] = &[
    "/etc/ld.so.preload",
    "/lib/libselinux.so",  // If not legitimate
    "/lib64/libselinux.so",
];

/// Check if a module name matches known rootkit signatures
pub fn is_known_rootkit_module(name: &str) -> Option<&'static str> {
    let name_lower = name.to_lowercase();

    for (pattern, description) in KNOWN_ROOTKIT_MODULES {
        if name_lower == *pattern || name_lower.contains(pattern) {
            return Some(description);
        }
    }

    None
}

/// Check if a module name looks suspicious based on patterns
pub fn is_suspicious_module_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();

    // Very short names (1-2 chars) that aren't known legitimate modules
    if name.len() <= 2 {
        // Common legitimate 2-char kernel module names
        let legitimate_short = [
            "ip", "dm", "sd", "sr", "sg", "md", // Block/storage
            "mc", "lp", "hv", "rp", // Media controller, parallel port, Hyper-V, rapl
            "ac", "at", "cx", "em", // ACPI, AT keyboard, Conexant, e1000 variants
            "hp", "i2", "mv", "nf", // HP laptop, I2C, Marvell, netfilter
            "pm", "rt", "sp", "tp", // Power mgmt, realtime, serial port, thinkpad
            "xt", // Xen/netfilter xt tables
        ];
        if !legitimate_short.contains(&name_lower.as_str()) {
            return true;
        }
    }

    // Names starting with a dot (hidden)
    if name.starts_with('.') {
        return true;
    }

    // Check suspicious patterns
    for pattern in SUSPICIOUS_MODULE_PATTERNS {
        if name_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check if a process name is suspicious
pub fn is_suspicious_process_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();

    for pattern in SUSPICIOUS_PROCESS_NAMES {
        if name_lower.contains(pattern) {
            return true;
        }
    }

    // Check for names that are all whitespace or dots
    if name.chars().all(|c| c == '.' || c == ' ') && !name.is_empty() {
        return true;
    }

    // Check for very long names (potential buffer overflow attempt)
    if name.len() > 256 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_rootkit_detection() {
        assert!(is_known_rootkit_module("diamorphine").is_some());
        assert!(is_known_rootkit_module("reptile").is_some());
        assert!(is_known_rootkit_module("legitimate_module").is_none());
    }

    #[test]
    fn test_suspicious_module_name() {
        assert!(is_suspicious_module_name(".hidden"));
        assert!(is_suspicious_module_name("a"));
        assert!(!is_suspicious_module_name("ext4"));
    }

    #[test]
    fn test_suspicious_process_name() {
        assert!(is_suspicious_process_name("xmrig"));
        assert!(is_suspicious_process_name("...."));
        assert!(!is_suspicious_process_name("bash"));
    }
}
