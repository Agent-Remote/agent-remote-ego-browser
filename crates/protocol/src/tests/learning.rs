use super::*;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::os::unix::fs::PermissionsExt;

struct TestBundle {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    key: SigningKey,
    data_path: PathBuf,
}

impl Drop for TestBundle {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        let _ = fs::set_permissions(
            self.root.join("learnings"),
            fs::Permissions::from_mode(0o700),
        );
        let _ = fs::set_permissions(
            self.root.join("learnings/example"),
            fs::Permissions::from_mode(0o700),
        );
        let _ = fs::set_permissions(&self.data_path, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(
            self.root.join("manifest.json"),
            fs::Permissions::from_mode(0o600),
        );
    }
}

fn create_bundle() -> TestBundle {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().canonicalize().expect("canonical root");
    let data_directory = root.join("learnings/example");
    fs::create_dir_all(&data_directory).expect("learning directories");
    let data_path = data_directory.join("note.md");
    let data = b"verified learning\n";
    fs::write(&data_path, data).expect("learning file");
    fs::set_permissions(&data_path, fs::Permissions::from_mode(0o400))
        .expect("read-only learning file");
    fs::set_permissions(&data_directory, fs::Permissions::from_mode(0o500))
        .expect("read-only learning directory");
    fs::set_permissions(
        data_directory.parent().expect("learning parent"),
        fs::Permissions::from_mode(0o500),
    )
    .expect("read-only learning parent");

    let key = SigningKey::generate(&mut OsRng);
    let mut manifest = LearningBundleManifest {
        bundle_version: "2026.09.1".into(),
        skill_version: "1.2.3".into(),
        local_ego_browser_runtime_version: "0.4.7.4".into(),
        protocol_versions: vec![crate::PROTOCOL_VERSION.into()],
        files: vec![LearningFile {
            path: "learnings/example/note.md".into(),
            size_bytes: data.len() as u64,
            sha256: hex_digest(data),
        }],
        signing_key_id: "test".into(),
        signature: String::new(),
    };
    manifest.signature = STANDARD.encode(
        key.sign(&manifest.signed_bytes().expect("manifest"))
            .to_bytes(),
    );
    let manifest_path = root.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o400))
        .expect("read-only manifest");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).expect("read-only bundle root");
    TestBundle {
        _temporary: temporary,
        root,
        key,
        data_path,
    }
}

#[test]
fn verifies_signed_read_only_bundle_and_versions() {
    let bundle = create_bundle();
    let verified =
        verify_learning_bundle_details(&bundle.root, &bundle.key.verifying_key().to_bytes())
            .expect("verified bundle");
    assert_eq!(verified.skill_version, "1.2.3");
    assert_eq!(verified.local_ego_browser_runtime_version, "0.4.7.4");
    assert!(verified.digest.starts_with("sha256:"));
    assert_eq!(
        verify_learning_bundle(
            &bundle.root,
            &bundle.key.verifying_key().to_bytes(),
            "1.2.3",
            "0.4.7.4",
        )
        .expect("compatible bundle"),
        verified.digest
    );
}

#[test]
fn rejects_tampered_and_writable_bundle_files() {
    let bundle = create_bundle();
    fs::set_permissions(&bundle.data_path, fs::Permissions::from_mode(0o600))
        .expect("make file writable");
    assert!(matches!(
        verify_learning_bundle_details(&bundle.root, &bundle.key.verifying_key().to_bytes()),
        Err(LearningBundleError::WritableBundle)
    ));
    fs::write(&bundle.data_path, b"tampered learning\n").expect("tamper file");
    fs::set_permissions(&bundle.data_path, fs::Permissions::from_mode(0o400))
        .expect("restore read-only mode");
    assert!(matches!(
        verify_learning_bundle_details(&bundle.root, &bundle.key.verifying_key().to_bytes()),
        Err(LearningBundleError::FileMismatch(_))
    ));
}

#[test]
fn rejects_hard_links_writable_directories_and_unlisted_directories() {
    let bundle = create_bundle();
    let data_directory = bundle.data_path.parent().expect("data directory");
    fs::set_permissions(data_directory, fs::Permissions::from_mode(0o700))
        .expect("make data directory writable");
    assert!(matches!(
        verify_learning_bundle_details(&bundle.root, &bundle.key.verifying_key().to_bytes()),
        Err(LearningBundleError::WritableBundle)
    ));

    let hard_link = data_directory.join("linked-note.md");
    fs::hard_link(&bundle.data_path, &hard_link).expect("hard link learning file");
    fs::set_permissions(data_directory, fs::Permissions::from_mode(0o500))
        .expect("restore read-only directory");
    assert!(matches!(
        verify_learning_bundle_details(&bundle.root, &bundle.key.verifying_key().to_bytes()),
        Err(LearningBundleError::FileMismatch(_))
    ));

    fs::set_permissions(data_directory, fs::Permissions::from_mode(0o700))
        .expect("make data directory writable for cleanup");
    fs::remove_file(&hard_link).expect("remove hard link");
    fs::set_permissions(data_directory, fs::Permissions::from_mode(0o500))
        .expect("restore read-only directory");
    fs::set_permissions(&bundle.root, fs::Permissions::from_mode(0o700))
        .expect("make root writable");
    let extra = bundle.root.join("unlisted-empty-directory");
    fs::create_dir(&extra).expect("create unlisted directory");
    fs::set_permissions(&extra, fs::Permissions::from_mode(0o500))
        .expect("make unlisted directory read-only");
    fs::set_permissions(&bundle.root, fs::Permissions::from_mode(0o500))
        .expect("restore read-only root");
    assert!(matches!(
        verify_learning_bundle_details(&bundle.root, &bundle.key.verifying_key().to_bytes()),
        Err(LearningBundleError::UnlistedPath(_))
    ));
}

#[test]
fn rejects_wrong_signing_key_and_version() {
    let bundle = create_bundle();
    let other = SigningKey::generate(&mut OsRng);
    assert!(matches!(
        verify_learning_bundle_details(&bundle.root, &other.verifying_key().to_bytes()),
        Err(LearningBundleError::InvalidSignature)
    ));
    assert!(matches!(
        verify_learning_bundle(
            &bundle.root,
            &bundle.key.verifying_key().to_bytes(),
            "9.9.9",
            "0.4.7.4"
        ),
        Err(LearningBundleError::VersionMismatch)
    ));
}
