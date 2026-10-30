//! Explicit legacy fixtures: normal CLI initialization creates SQLite catalogs.
use archive_ledger::{
    CatalogRegistry, KnownArchive, V2ArchiveInitialization, V2OriginStore, V2ProjectionDb,
};
use std::{fs, path::Path};

pub fn legacy_archive(
    temp: &Path,
    name: &str,
    id: &str,
    make_default: bool,
) -> V2ArchiveInitialization {
    let root = temp.join("data/archive-ledger/archives").join(id);
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    let initialized =
        archive_ledger::initialize_v2_archive(&root, id, name, 1_700_000_000_000).unwrap();
    let store = V2OriginStore::open(root.join("canonical")).unwrap();
    V2ProjectionDb::create_from_store(&store, root.join("archive.db")).unwrap();
    let path = temp.join("config/archive-ledger/catalogs.json");
    let registry: CatalogRegistry = if path.exists() {
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap()
    } else {
        CatalogRegistry::default()
    };
    let mut archives = registry.archives().to_vec();
    archives.push(KnownArchive {
        archive_id: id.into(),
        display_name: name.into(),
        root,
    });
    archives.sort_by(|a, b| a.archive_id.cmp(&b.archive_id));
    let default = if make_default || registry.default_archive_id().is_none() {
        id
    } else {
        registry.default_archive_id().unwrap()
    };
    // Serialize the actual registry type at an explicit fixture path. Changing
    // process-global XDG variables would race concurrently running tests.
    let registry: CatalogRegistry = serde_json::from_value(
        serde_json::json!({"version":1,"default_archive_id":default,"archives":archives}),
    )
    .unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(&registry).unwrap()).unwrap();
    initialized
}
