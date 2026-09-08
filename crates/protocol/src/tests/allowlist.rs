use super::*;
use std::io::Write;
use std::os::unix::fs::symlink;

#[test]
fn canonical_digest_is_stable_across_root_order() {
    let first = tempfile::tempdir().expect("first root");
    let second = tempfile::tempdir().expect("second root");
    let first_path = first.path().canonicalize().expect("first path");
    let second_path = second.path().canonicalize().expect("second path");
    let forward = Allowlist::new(
        vec![first_path.clone(), second_path.clone()],
        2,
        AllowlistLimits::default(),
    )
    .expect("forward allowlist");
    let reverse = Allowlist::new(vec![second_path, first_path], 2, AllowlistLimits::default())
        .expect("reverse allowlist");
    assert_eq!(forward.roots(), reverse.roots());
    assert_eq!(
        forward.roots_digest().expect("forward digest"),
        reverse.roots_digest().expect("reverse digest")
    );
}

#[test]
fn input_open_rejects_escape_symlink_hardlink_and_limits() {
    let root = tempfile::tempdir().expect("allowlist root");
    let outside = tempfile::tempdir().expect("outside root");
    let root_path = root.path().canonicalize().expect("root path");
    let allowlist = Allowlist::new(
        vec![root_path.clone()],
        3,
        AllowlistLimits {
            max_file_bytes: 16,
            max_total_bytes: 20,
            max_file_count: 2,
        },
    )
    .expect("allowlist");
    let input = root_path.join("input.txt");
    fs::write(&input, b"hello").expect("input file");
    assert_eq!(
        allowlist
            .open_input(&input, 0, 0)
            .expect("validated input")
            .read_to_end()
            .expect("input bytes"),
        b"hello"
    );
    let changing = root_path.join("changing.txt");
    fs::write(&changing, b"four").expect("changing file");
    let opened = allowlist
        .open_input(&changing, 0, 0)
        .expect("open bounded input");
    OpenOptions::new()
        .append(true)
        .open(&changing)
        .expect("open changing file")
        .write_all(b"more")
        .expect("grow changing file");
    assert!(matches!(
        opened.read_to_end(),
        Err(AllowlistError::ChangedDuringOpen)
    ));

    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, b"outside").expect("outside file");
    let outside_file = outside_file.canonicalize().expect("outside path");
    assert!(matches!(
        allowlist.open_input(&outside_file, 0, 0),
        Err(AllowlistError::OutsideRoot)
    ));
    let link = root_path.join("link.txt");
    symlink(&outside_file, &link).expect("symlink");
    assert!(matches!(
        allowlist.open_input(&link, 0, 0),
        Err(AllowlistError::Symlink)
    ));
    let hard_link = root_path.join("hard.txt");
    fs::hard_link(&input, &hard_link).expect("hard link");
    assert!(matches!(
        allowlist.open_input(&input, 0, 0),
        Err(AllowlistError::HardLink)
    ));
    assert!(matches!(
        allowlist.open_input(&outside_file, 21, 0),
        Err(AllowlistError::TotalTooLarge)
    ));
    assert!(matches!(
        allowlist.open_input(&outside_file, 0, 2),
        Err(AllowlistError::FileCountTooLarge)
    ));
}

#[test]
fn output_open_stays_inside_validated_parent() {
    let root = tempfile::tempdir().expect("allowlist root");
    let root_path = root.path().canonicalize().expect("root path");
    let allowlist =
        Allowlist::new(vec![root_path.clone()], 1, AllowlistLimits::default()).expect("allowlist");
    let destination = root_path.join("download.bin");
    let validated = allowlist
        .validate_output(&destination, 0, 0, 4)
        .expect("validated output");
    validated
        .open_for_write(false)
        .expect("opened output")
        .write_all(b"data")
        .expect("write output");
    assert_eq!(fs::read(destination).expect("read output"), b"data");

    let replacement = allowlist
        .validate_output(&root_path.join("download.bin"), 0, 0, 7)
        .expect("validated replacement");
    let incoming = replacement
        .staging_path("test-token")
        .expect("incoming path");
    assert!(incoming.starts_with(&root_path));
    fs::write(&incoming, b"ignored").expect("incoming download");
    replacement
        .replace_atomically(b"updated", "test-token")
        .expect("atomic replacement");
    replacement
        .remove_staging("test-token")
        .expect("incoming cleanup");
    assert_eq!(
        fs::read(root_path.join("download.bin")).expect("read replacement"),
        b"updated"
    );
}
