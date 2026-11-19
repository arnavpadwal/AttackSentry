use std::process::Command;

pub struct KillSwitch {
    active: bool,
}

impl KillSwitch {
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        let active = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=AttackSentry Emergency Isolation",
            ])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        #[cfg(not(target_os = "windows"))]
        let active = Command::new("iptables")
            .args([
                "-C",
                "OUTPUT",
                "-m",
                "comment",
                "--comment",
                "AttackSentryEmergencyIsolation",
                "-j",
                "DROP",
            ])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        Self { active }
    }

    pub fn is_engaged(&self) -> bool {
        self.active
    }

    pub fn engage(&mut self) {
        if !self.active {
            println!("[KILL SWITCH] ENGAGING: Blocking all outbound network traffic...");

            #[cfg(target_os = "windows")]
            let status = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=AttackSentry Emergency Isolation",
                    "dir=out",
                    "action=block",
                    "enable=yes",
                ])
                .status();

            #[cfg(not(target_os = "windows"))]
            let status = Command::new("iptables")
                .args([
                    "-I",
                    "OUTPUT",
                    "1",
                    "-m",
                    "comment",
                    "--comment",
                    "AttackSentryEmergencyIsolation",
                    "-j",
                    "DROP",
                ])
                .status();

            match status {
                Ok(s) if s.success() => {
                    println!("[KILL SWITCH] Traffic blocked successfully.");
                    self.active = true;
                }
                Ok(s) => eprintln!("[KILL SWITCH] Command failed with status: {}", s),
                Err(e) => eprintln!(
                    "[KILL SWITCH] Failed to execute firewall command (requires admin/root): {}",
                    e
                ),
            }
        }
    }

    pub fn disengage(&mut self) {
        if self.active {
            println!("[KILL SWITCH] DISENGAGING: Restoring network access...");

            #[cfg(target_os = "windows")]
            let status = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    "name=AttackSentry Emergency Isolation",
                ])
                .status();

            #[cfg(not(target_os = "windows"))]
            let status = Command::new("iptables")
                .args([
                    "-D",
                    "OUTPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "AttackSentryEmergencyIsolation",
                    "-j",
                    "DROP",
                ])
                .status();

            match status {
                Ok(s) if s.success() => {
                    println!("[KILL SWITCH] Traffic restored successfully.");
                    self.active = false;
                }
                Ok(s) => eprintln!("[KILL SWITCH] Command failed with status: {}", s),
                Err(e) => eprintln!(
                    "[KILL SWITCH] Failed to execute firewall command (requires admin/root): {}",
                    e
                ),
            }
        }
    }
}
