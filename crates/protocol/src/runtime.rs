use crate::ProtocolError;

const MAX_PROBE_BYTES: usize = 4096;

/// Parsed output of `ego-browser --version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeProbe {
    pub ego_browser_version: String,
    pub chromium_version: String,
    pub node_version: String,
}

/// Parse the pinned three-line ego-browser runtime version response.
pub fn parse_runtime_probe(bytes: &[u8]) -> Result<RuntimeProbe, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_PROBE_BYTES {
        return Err(ProtocolError::InvalidInner("runtime probe size"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProtocolError::InvalidInner("runtime probe encoding"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 3 {
        return Err(ProtocolError::InvalidInner("runtime probe lines"));
    }
    let ego_browser_version = parse_version_line(lines[0], "ego-browser ")?;
    let chromium_version = parse_version_line(lines[1].trim(), "chromium ")?;
    let node_version = parse_version_line(lines[2].trim(), "node v")?;
    Ok(RuntimeProbe {
        ego_browser_version,
        chromium_version,
        node_version,
    })
}

/// Parse a runtime version response when the executable chooses either output
/// stream for its non-interactive response.
///
/// The official ego lite runtime currently writes `--version` to stderr. A
/// few wrappers write to stdout instead, and test/runtime shims can split the
/// response across both streams. Keep the stream handling in one place so all
/// callers enforce the same strict three-line contract.
pub fn parse_runtime_probe_output(
    stdout: &[u8],
    stderr: &[u8],
) -> Result<RuntimeProbe, ProtocolError> {
    for candidate in [stdout, stderr] {
        if let Ok(probe) = parse_runtime_probe(candidate) {
            return Ok(probe);
        }
    }

    let combined_len = stdout.len().saturating_add(stderr.len());
    if combined_len <= MAX_PROBE_BYTES {
        let mut combined = Vec::with_capacity(combined_len);
        combined.extend_from_slice(stdout);
        combined.extend_from_slice(stderr);
        if let Ok(probe) = parse_runtime_probe(&combined) {
            return Ok(probe);
        }

        combined.clear();
        combined.extend_from_slice(stderr);
        combined.extend_from_slice(stdout);
        if let Ok(probe) = parse_runtime_probe(&combined) {
            return Ok(probe);
        }
    }

    Err(ProtocolError::InvalidInner("runtime probe streams"))
}

fn parse_version_line(line: &str, prefix: &str) -> Result<String, ProtocolError> {
    let value = line
        .strip_prefix(prefix)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or(ProtocolError::InvalidInner("runtime probe format"))?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(ProtocolError::InvalidInner("runtime probe version"));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
#[path = "tests/runtime.rs"]
mod tests;
