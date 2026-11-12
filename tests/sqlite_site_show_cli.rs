use archive_ledger::SqliteCatalog;
use serde_json::Value;
use std::process::{Command, Output};
use tempfile::TempDir;

struct Fixture {
    temp: TempDir,
    catalog: SqliteCatalog,
}
impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
        catalog.connection().execute_batch(
            "INSERT INTO sites(site_id,display_name,site_kind,description,status) VALUES
              ('home','Home','home','Primary storage','active'),
              ('away','Offsite','offsite',NULL,'active'),
              ('empty','Sam','offsite',NULL,'active');
             INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability) VALUES
              ('z','sd03','disk','unavailable','active','home','intermittent'),
              ('a','disk10','disk','unavailable','active','home','online'),
              ('retired','old disk','disk','unavailable','retired','home','offline'),
              ('backup','sd23','disk','unavailable','active','away','offline'),
              ('unassigned','spare','disk','unavailable','active',NULL,'offline');"
        ).unwrap();
        Self { temp, catalog }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_archive"))
            .env_remove("ARCHIVE_LEDGER_ARCHIVE")
            .arg("--archive")
            .arg(self.temp.path())
            .args(args)
            .output()
            .unwrap()
    }
    fn show(&self, site: &str) -> Value {
        let output = self.run(&["site", "show", site, "--json"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn data_version(&self) -> i64 {
        self.catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap()
    }
}

#[test]
fn site_show_groups_current_devices_preserves_json_and_does_not_write() {
    let f = Fixture::new();
    let version = f.data_version();
    let json = f.show("Home");
    assert_eq!(json["version"], 3);
    assert_eq!(json["items"][0]["site_id"], "home");
    assert_eq!(json["items"][0]["description"], "Primary storage");
    assert_eq!(json["device_count"], 3);
    let devices = json["devices"].as_array().unwrap();
    assert_eq!(
        devices
            .iter()
            .map(|d| d["display_name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["disk10", "old disk", "sd03"]
    );
    assert_eq!(devices[1]["status"], "retired");
    assert!(devices.iter().all(|d| d["current_site_id"] == "home"));
    assert_eq!(f.show("home"), json);
    let output = f.run(&["site", "show", "Home"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.starts_with("Name: Home\nKind: home\nStatus: active\nDescription: Primary storage\n")
    );
    assert!(text.contains("\nDevices: 3\n"));
    assert!(text.contains(
        "\n  disk10\n    Kind: disk\n    Status: active\n    Expected availability: online\n"
    ));
    assert!(text.contains("\n  old disk\n    Kind: disk\n    Status: retired\n"));
    assert!(!text.contains("Site ID:"));
    assert!(!text.contains("Device ID:"));
    assert!(!text.contains("sd23"));
    assert!(!text.contains("spare"));
    assert!(text.lines().all(|line| line.len() < 60));
    assert_eq!(f.data_version(), version);
}

#[test]
fn site_show_reflects_device_move_and_handles_empty_or_unknown_sites() {
    let f = Fixture::new();
    let empty = f.show("Sam");
    assert_eq!(empty["device_count"], 0);
    assert_eq!(empty["devices"], serde_json::json!([]));
    let output = f.run(&["site", "show", "Sam"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Devices: 0\n  No Devices assigned to this Site."));
    assert!(!text.contains("Description:"));
    let moved = f.run(&["device", "move", "sd03", "--to", "Offsite"]);
    assert!(
        moved.status.success(),
        "{}",
        String::from_utf8_lossy(&moved.stderr)
    );
    let version = f.data_version();
    let home = f.show("Home");
    let away = f.show("Offsite");
    assert_eq!(home["device_count"], 2);
    assert_eq!(away["device_count"], 2);
    assert!(!home["devices"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["device_id"] == "z"));
    assert!(away["devices"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["device_id"] == "z"));
    assert!(!f.run(&["site", "show", "Unknown"]).status.success());
    assert_eq!(f.data_version(), version);
}
