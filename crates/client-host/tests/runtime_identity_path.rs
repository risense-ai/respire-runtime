use respire_client_host::config::normalize_control_path;
use respire_client_host::identity::{auth_session_identity, AuthSessionIdentity};

#[test]
fn identity_path_retains_missing_suffix_and_strict_parent_boundary() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let missing = root.join("empty").join("session.json");
    assert_eq!(normalize_control_path(&missing)?, missing);
    assert!(matches!(
        auth_session_identity(&root.join("empty"), |_| "synthetic".to_owned())?,
        AuthSessionIdentity::Absent
    ));
    let parent = std::path::Path::new("empty/../data");
    let error = normalize_control_path(parent).unwrap_err();
    assert_eq!(
        error.to_string(),
        "host control does not support parent traversal"
    );
    let file = root.join("file");
    std::fs::write(&file, b"synthetic")?;
    assert_eq!(
        normalize_control_path(&file.join("session.json"))
            .unwrap_err()
            .to_string(),
        "host control ancestor is not a directory"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn identity_path_does_not_turn_redirects_into_missing_profiles() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let real = root.join("real");
    std::fs::create_dir(&real)?;
    std::fs::write(real.join("session.json"), b"{}")?;
    let link = root.join("link");
    symlink(&real, &link)?;
    for path in [link.clone(), link.join("session.json")] {
        assert!(normalize_control_path(&path)
            .unwrap_err()
            .to_string()
            .contains("symlink/reparse point"));
    }
    assert!(auth_session_identity(&link, |_| "synthetic".to_owned()).is_err());
    let dangling = root.join("dangling");
    symlink(root.join("never-created"), &dangling)?;
    assert!(auth_session_identity(&dangling, |_| "synthetic".to_owned()).is_err());
    Ok(())
}
