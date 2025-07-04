use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::fs;

pub(super) fn create_test_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp dir")
}

pub(super) async fn create_test_binary(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content)
        .await
        .expect("Failed to write test binary");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .await
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)
            .await
            .expect("Failed to set permissions");
    }

    path
}

pub(super) fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub(super) fn create_test_executable_content(version: &str) -> Vec<u8> {
    let content = format!(
        "#!/bin/bash\necho 'Test DNSPX Binary Version {}'\nexit 0\n",
        version
    );
    content.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let data = b"test data";
        let checksum = calculate_sha256(data);
        assert_eq!(checksum.len(), 64);
    }

    #[tokio::test]
    async fn test_create_test_binary() {
        let temp_dir = create_test_dir();
        let content = b"test content";
        let path = create_test_binary(temp_dir.path(), "test", content).await;

        assert!(path.exists());
        let read_content = fs::read(path).await.unwrap();
        assert_eq!(read_content, content);
    }
}
