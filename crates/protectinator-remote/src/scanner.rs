//! Remote scanner orchestration

use crate::types::{RemoteHost, RemoteScanResults, ScanMode};
use crate::{agent, agentless};

/// Scanner that coordinates remote host security scanning
pub struct RemoteScanner {
    host: RemoteHost,
    mode: ScanMode,
    skip_vulnerability: bool,
}

impl RemoteScanner {
    pub fn new(host: RemoteHost, mode: ScanMode) -> Self {
        Self {
            host,
            mode,
            skip_vulnerability: false,
        }
    }

    pub fn skip_vulnerability(mut self, skip: bool) -> Self {
        self.skip_vulnerability = skip;
        self
    }

    /// Run the scan
    pub fn scan(&self) -> Result<RemoteScanResults, String> {
        match self.mode {
            ScanMode::Agent => agent::scan(&self.host),
            ScanMode::Agentless => agentless::scan(&self.host, self.skip_vulnerability),
        }
    }
}
