//! Collection protection distributions from one current-state catalog snapshot.
use super::*;
use archive_ledger::{sqlite_queries::verified_copy_predicate, SqliteCatalog};

#[derive(Debug, Serialize)]
struct ProtectionSummary {
    total_files: u64,
    without_expected_checksum: u64,
    present_copies: BTreeMap<u64, u64>,
    recent_verified_copies: BTreeMap<u64, u64>,
    present_known_sites: BTreeMap<u64, u64>,
    recent_verified_known_sites: BTreeMap<u64, u64>,
    present_files_with_unknown_site: u64,
    recent_verified_files_with_unknown_site: u64,
}

pub(super) fn execute(
    cli: &Cli,
    catalog: &SqliteCatalog,
    selector: Option<&str>,
    stale_after: &str,
) -> Result<u8, AppError> {
    let age = parse_file_evidence_age(stale_after).map_err(|message| {
        AppError::Input(message.replace("--verified-within", "--stale-after"))
    })?;
    let as_of = now_utc_ms()?;
    let transaction = catalog.connection().unchecked_transaction()?;
    let state = catalog.registry_state(selector.is_some())?;
    let collection = match selector {
        Some(selector) => select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?,
        None if state.collections.len() == 1 => state.collections[0].clone(),
        None => return Err(AppError::Input("specify a Collection name or ID".into())),
    };
    let summary = protection_summary(catalog, &collection.collection_id, as_of, age)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version":3, "catalog_format":"sqlite", "items":[collection],
                "summary":summary, "stale_after_ms":age, "as_of_utc_ms":as_of,
                "evidence":"cached_catalog", "policy_evaluated":false,
                "site_counts":"known_sites_lower_bound"
            }))?
        );
    } else {
        println!("Name: {}", collection.display_name);
        println!("Status: {}", collection.status);
        if let Some(description) = &collection.description {
            println!("Description: {description}");
        }
        if let Some(site) = collection.home_site_id.as_ref() {
            let name = state
                .sites
                .iter()
                .find(|s| &s.site_id == site)
                .map_or(site.as_str(), |s| s.display_name.as_str());
            println!("Home Site: {name}");
        }
        if let Some(policy) = collection.policy_id.as_ref() {
            let name = state
                .policies
                .iter()
                .find(|p| &p.policy_id == policy)
                .map_or(policy.as_str(), |p| p.display_name.as_str());
            println!("Backup policy: {name} (not evaluated)");
        }
        println!("\nFiles");
        println!("  Total tracked: {}", summary.total_files);
        println!(
            "  Without expected checksum: {}",
            summary.without_expected_checksum
        );
        println!("\nProtection gaps");
        println!("  No present copy: {}", bucket(&summary.present_copies, 0));
        println!(
            "  Only one present copy: {}",
            bucket(&summary.present_copies, 1)
        );
        println!(
            "  No recently verified copy: {}",
            bucket(&summary.recent_verified_copies, 0)
        );
        println!(
            "  Recently verified at only one known Site: {}",
            bucket(&summary.recent_verified_known_sites, 1)
        );
        println!("\nVerification window: {stale_after}");
        print_distribution(
            "Files by copy count",
            ("copy", "copies"),
            &summary.present_copies,
            &summary.recent_verified_copies,
            summary.total_files,
        );
        print_distribution(
            "Files by known Site count",
            ("Site", "Sites"),
            &summary.present_known_sites,
            &summary.recent_verified_known_sites,
            summary.total_files,
        );
        println!("\nSite information");
        println!(
            "  Files with copies at an unknown Site: {}",
            summary.present_files_with_unknown_site
        );
        println!(
            "  Of those, with recent verification at an unknown Site: {}",
            summary.recent_verified_files_with_unknown_site
        );
        println!("  Unknown Sites are excluded from Site counts.");
        println!("\nPercentages: Share of all tracked files. Copies count Locations, which may share a Device.");
        println!("Recently verified: Present, matching checksum, checked within {stale_after}.");
        println!("Evidence: Cached catalog; drives have not been checked.");
        println!("Backup policy: Not evaluated.");
    }
    transaction.commit()?;
    Ok(EXIT_OK)
}

fn bucket(distribution: &BTreeMap<u64, u64>, count: u64) -> u64 {
    distribution.get(&count).copied().unwrap_or(0)
}

fn print_distribution(
    label: &str,
    units: (&str, &str),
    present: &BTreeMap<u64, u64>,
    verified: &BTreeMap<u64, u64>,
    total: u64,
) {
    println!("\n{label}");
    let counts = present
        .keys()
        .chain(verified.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for count in counts {
        let format_count = |files: u64| {
            let percent = if total == 0 {
                0.0
            } else {
                files as f64 * 100.0 / total as f64
            };
            format!("{files} ({percent:.1}%)")
        };
        let unit = if count == 1 { units.0 } else { units.1 };
        println!("  {count} {unit}");
        println!("    Present: {}", format_count(bucket(present, count)));
        println!(
            "    Recently verified: {}",
            format_count(bucket(verified, count))
        );
    }
}

fn protection_summary(
    catalog: &SqliteCatalog,
    collection: &str,
    as_of: u64,
    age: u64,
) -> Result<ProtectionSummary, AppError> {
    let recent = format!(
        "({} AND f.last_success_time_utc_ms BETWEEN ?2 AND ?3)",
        verified_copy_predicate("f", "o")
    );
    let site = "COALESCE(l.site_id,d.current_site_id)";
    // Include Objects without File rows. Each grouped row is consumed immediately;
    // memory grows with histogram buckets, not with the number of expected paths.
    // Group by the unique Collection/path key in index order to avoid sorting
    // every joined File row by Object ID.
    let sql = format!(
        "SELECT o.expected_blake3 IS NULL,
        COUNT(CASE WHEN f.presence='present' THEN f.location_id END),
        COUNT(CASE WHEN {recent} THEN f.location_id END),
        COUNT(DISTINCT CASE WHEN f.presence='present' THEN {site} END),
        COUNT(DISTINCT CASE WHEN {recent} THEN {site} END),
        MAX(CASE WHEN f.presence='present' AND {site} IS NULL THEN 1 ELSE 0 END),
        MAX(CASE WHEN {recent} AND {site} IS NULL THEN 1 ELSE 0 END)
        FROM objects o LEFT JOIN files f ON f.object_id=o.object_id
        LEFT JOIN locations l ON l.location_id=f.location_id
        LEFT JOIN devices d ON d.device_id=l.device_id
        WHERE o.collection_id=?1 GROUP BY o.collection_id,o.relative_path_encoding,o.relative_path_bytes"
    );
    let mut result = ProtectionSummary {
        total_files: 0,
        without_expected_checksum: 0,
        present_copies: BTreeMap::from([(0, 0)]),
        recent_verified_copies: BTreeMap::from([(0, 0)]),
        present_known_sites: BTreeMap::from([(0, 0)]),
        recent_verified_known_sites: BTreeMap::from([(0, 0)]),
        present_files_with_unknown_site: 0,
        recent_verified_files_with_unknown_site: 0,
    };
    let mut statement = catalog.connection().prepare(&sql)?;
    let mut rows = statement.query(params![
        collection,
        as_of.saturating_sub(age) as i64,
        as_of as i64
    ])?;
    while let Some(row) = rows.next()? {
        result.total_files += 1;
        result.without_expected_checksum += row.get::<_, i64>(0)? as u64;
        for (index, distribution) in [
            &mut result.present_copies,
            &mut result.recent_verified_copies,
            &mut result.present_known_sites,
            &mut result.recent_verified_known_sites,
        ]
        .into_iter()
        .enumerate()
        {
            *distribution
                .entry(row.get::<_, i64>(index + 1)? as u64)
                .or_default() += 1;
        }
        result.present_files_with_unknown_site += row.get::<_, i64>(5)? as u64;
        result.recent_verified_files_with_unknown_site += row.get::<_, i64>(6)? as u64;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_distributions_count_paths_locations_and_known_sites_separately() {
        let temp = tempfile::TempDir::new().unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('c','Files','active'),('other','Other','active'),('empty','Empty','active');
            INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('home','Home','home','active'),('office','Office','office','active');
            INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,expected_availability) VALUES('disk','Disk','disk','unavailable','active','offline');
            INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status) VALUES('root','disk','Root','unavailable',X'2f','utf8','/','active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('home1','Home1','service','home','offline','active'),('home2','Home2','service','home','offline','retired'),('office','Office','service','office','offline','active');
            INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,status) VALUES('unknown','Unknown','filesystem','root',X'','utf8','','disk','offline','active');").unwrap();
        for id in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"] {
            catalog.connection().execute("INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3) VALUES(?1,?2,'utf8',?3,?1,?4)", params![id, if id=="j" {"other"} else {"c"},id.as_bytes(),(id!="g").then_some(vec![0u8;32])]).unwrap();
        }
        for (id, location, presence, integrity, time) in [
            ("a", "home1", "present", "verified", 100),
            ("a", "home2", "present", "verified", 100),
            ("b", "home1", "present", "verified", 101),
            ("b", "office", "present", "verified", 101),
            ("c", "home1", "missing", "verified", 101),
            ("d", "home1", "present", "damaged", 101),
            ("e", "unknown", "present", "verified", 101),
            ("g", "home1", "present", "unverified", 101),
            ("h", "home1", "present", "verified", 201),
            ("i", "home1", "present", "verified", 99),
            ("j", "home1", "present", "verified", 101),
        ] {
            let check = if presence == "missing" {
                "missing"
            } else if integrity == "damaged" {
                "mismatch"
            } else {
                "ok"
            };
            catalog.connection().execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES(?1,?2,?3,?4,?5,?6,zeroblob(32),?5)",params![id,location,presence,integrity,time,check]).unwrap();
        }
        let before: i64 = catalog
            .connection()
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        let summary = protection_summary(&catalog, "c", 200, 100).unwrap();
        assert_eq!(summary.total_files, 9);
        assert_eq!(summary.without_expected_checksum, 1);
        assert_eq!(
            summary.present_copies,
            BTreeMap::from([(0, 2), (1, 5), (2, 2)])
        );
        assert_eq!(
            summary.recent_verified_copies,
            BTreeMap::from([(0, 6), (1, 1), (2, 2)])
        );
        assert_eq!(
            summary.present_known_sites,
            BTreeMap::from([(0, 3), (1, 5), (2, 1)])
        );
        assert_eq!(
            summary.recent_verified_known_sites,
            BTreeMap::from([(0, 7), (1, 1), (2, 1)])
        );
        assert_eq!(summary.present_files_with_unknown_site, 1);
        assert_eq!(summary.recent_verified_files_with_unknown_site, 1);
        // A filesystem Location inherits its Device's current Site, never a new Site per copy.
        catalog
            .connection()
            .execute(
                "UPDATE devices SET current_site_id='home' WHERE device_id='disk'",
                [],
            )
            .unwrap();
        let with_known_site = protection_summary(&catalog, "c", 200, 100).unwrap();
        assert_eq!(with_known_site.present_files_with_unknown_site, 0);
        assert_eq!(
            with_known_site.present_known_sites,
            BTreeMap::from([(0, 2), (1, 6), (2, 1)])
        );
        let empty = protection_summary(&catalog, "empty", 200, 100).unwrap();
        assert_eq!(empty.total_files, 0);
        for histogram in [
            empty.present_copies,
            empty.recent_verified_copies,
            empty.present_known_sites,
            empty.recent_verified_known_sites,
        ] {
            assert_eq!(histogram, BTreeMap::from([(0, 0)]));
        }
        let after: i64 = catalog
            .connection()
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, before + 1); // Only the explicit Device update above wrote anything.
    }
}
