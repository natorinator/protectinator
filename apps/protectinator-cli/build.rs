use std::process::Command;

fn main() {
    // Embed build timestamp
    let now = chrono_lite();
    println!("cargo:rustc-env=BUILD_DATE={}", now);

    // Try jj for commit info first, then git
    if let Some(commit) = jj_commit() {
        println!("cargo:rustc-env=VCS_COMMIT={}", commit);
    } else if let Some(commit) = git_commit() {
        println!("cargo:rustc-env=VCS_COMMIT={}", commit);
    } else {
        println!("cargo:rustc-env=VCS_COMMIT=unknown");
    }

    // Don't rerun on every build — only when source changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}

fn jj_commit() -> Option<String> {
    let output = Command::new("jj")
        .args(["log", "--limit", "1", "--no-graph", "-T", "commit_id.short(8)", "-r", "@-"])
        .output()
        .ok()?;
    if output.status.success() {
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !hash.is_empty() {
            return Some(hash);
        }
    }
    None
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()?;
    if output.status.success() {
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !hash.is_empty() {
            return Some(hash);
        }
    }
    None
}

fn chrono_lite() -> String {
    // Simple date without pulling in chrono as a build dep
    let output = Command::new("date")
        .arg("+%Y-%m-%d")
        .output();
    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}
