use archive_ledger::SqliteCatalog;
use serde_json::Value;
use std::process::Command;

#[test]
fn copy_count_filter_supports_text_json_cursor_and_lossless_paths() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
    catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('c','Files','active');
        INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Home','home','active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('l','Disk','service','s','offline','active');
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3) VALUES
            ('a','c','utf8',X'61','a',zeroblob(32)),('b','c','utf8',X'620a63','b\nc',zeroblob(32));
        INSERT INTO files(object_id,location_id,presence,integrity) VALUES('a','l','present','unverified');").unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_archive"))
            .arg("--archive")
            .arg(temp.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    let base = [
        "file",
        "find",
        "--collection",
        "Files",
        "--copies-below",
        "1",
    ];
    assert_eq!(run(&base), b"b\\nc\n");
    let mut args = base.to_vec();
    args.push("--print0");
    assert_eq!(run(&args), b"b\nc\0");
    args = base.to_vec();
    args.push("--verified-copies");
    assert_eq!(run(&args), b"a\nb\\nc\n");
    args.extend(["--json", "--limit", "1"]);
    let first: Value = serde_json::from_slice(&run(&args)).unwrap();
    let cursor = first["next"].as_str().unwrap();
    args.extend(["--continue", cursor]);
    let second: Value = serde_json::from_slice(&run(&args)).unwrap();
    assert_eq!(second["objects"][0]["object_id"], "b");
    assert!(second["next"].is_null());
    assert_eq!(
        run(&[
            "file",
            "find",
            "--collection",
            "Files",
            "--copies-below",
            "0"
        ]),
        b""
    );
    for args in [
        vec!["file", "find", "--verified-copies"],
        vec!["file", "find", "--copies-below", "-1"],
        vec![
            "file",
            "find",
            "--copies-below",
            "2",
            "--copies-verified-within",
            "0d",
        ],
    ] {
        assert!(!Command::new(env!("CARGO_BIN_EXE_archive"))
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    }
}
