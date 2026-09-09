use super::*;

#[test]
fn parses_real_runtime_probe() {
    let probe =
        parse_runtime_probe(b"ego-browser 0.4.7.4\n  chromium 150.0.7871.101\n  node v24.18.0\n")
            .expect("probe");
    assert_eq!(probe.ego_browser_version, "0.4.7.4");
    assert_eq!(probe.chromium_version, "150.0.7871.101");
    assert_eq!(probe.node_version, "24.18.0");
}

#[test]
fn parses_expected_probe_from_stderr_or_split_streams() {
    let stderr = b"ego-browser 0.4.7.4\n  chromium 150.0.7871.101\n  node v24.18.0\n";
    let parsed = parse_runtime_probe_output(b"", stderr).expect("stderr probe");
    assert_eq!(parsed.ego_browser_version, "0.4.7.4");

    let split = parse_runtime_probe_output(
        b"ego-browser 0.4.7.4\n  chromium 150.0.7871.101\n",
        b"  node v24.18.0\n",
    )
    .expect("split probe");
    assert_eq!(split.node_version, "24.18.0");
}

#[test]
fn rejects_malformed_or_extra_runtime_probe_data() {
    for value in [
        b"ego-browser 0.4.7.4\nchromium 150\n".as_slice(),
        b"ego-browser 0.4.7.4\nchromium 150\nnode v24\nextra\n".as_slice(),
        b"ego-browser ../../bad\nchromium 150\nnode v24\n".as_slice(),
    ] {
        assert!(parse_runtime_probe(value).is_err());
    }
}
