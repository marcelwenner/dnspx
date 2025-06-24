use crate::adapters::update::release_analyzer::ReleaseAnalyzer;
use crate::config::models::{UpdateAutoPolicy, UpdateLevel};
use semver::Version;

fn create_test_analyzer() -> ReleaseAnalyzer {
    ReleaseAnalyzer::new()
}

fn create_test_policy(update_level: UpdateLevel) -> UpdateAutoPolicy {
    UpdateAutoPolicy {
        update_level,
        allow_breaking_changes: false,
        require_security_approval: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_simple_release_notes() {
        let analyzer = create_test_analyzer();

        let release_notes = "
## What's Changed
- Fix memory leak in DNS cache
- Add support for DoH compression
- Update dependencies for security patches
        ";

        let result = analyzer.analyze_release_notes(release_notes, "1.2.3");
        assert!(
            result.is_ok(),
            "Should successfully analyze simple release notes"
        );

        let metadata = result.unwrap();
        assert_eq!(metadata.version, Version::new(1, 2, 3));
        assert!(
            !metadata.has_breaking_changes,
            "Should not detect breaking changes"
        );
        assert!(!metadata.bug_fixes.is_empty(), "Should detect bug fixes");
    }

    #[test]
    fn test_analyze_security_release() {
        let analyzer = create_test_analyzer();

        let security_notes = "
## Security Update
- Fix vulnerability in DNS parsing (CVE-2024-1234)
- Update crypto dependencies
- Security patch for authentication bypass
        ";

        let result = analyzer
            .analyze_release_notes(security_notes, "1.2.4")
            .unwrap();
        assert!(result.security_fixes, "Should detect security fixes");
        assert!(result.version == Version::new(1, 2, 4));
    }

    #[test]
    fn test_analyze_breaking_changes() {
        let analyzer = create_test_analyzer();

        let breaking_notes = "
## Breaking Changes
- Remove deprecated API endpoints
- Change configuration file format
- 💥 Breaking: Update minimum supported version
        ";

        let result = analyzer
            .analyze_release_notes(breaking_notes, "2.0.0")
            .unwrap();
        assert!(
            result.has_breaking_changes,
            "Should detect breaking changes"
        );
        assert!(result.version == Version::new(2, 0, 0));
    }

    #[test]
    fn test_should_auto_update_patch_only() {
        let analyzer = create_test_analyzer();
        let policy = create_test_policy(UpdateLevel::PatchOnly);
        let current = Version::new(1, 2, 3);

        let patch_update = Version::new(1, 2, 4);
        let metadata = analyzer
            .analyze_release_notes("- Bug fix", "1.2.4")
            .unwrap();

        let should_update =
            analyzer.should_auto_update(&policy, &current, &patch_update, &metadata);
        assert!(
            should_update,
            "Should allow patch updates with PatchOnly policy"
        );

        let minor_update = Version::new(1, 3, 0);
        let minor_metadata = analyzer
            .analyze_release_notes("- New feature", "1.3.0")
            .unwrap();

        let should_update_minor =
            analyzer.should_auto_update(&policy, &current, &minor_update, &minor_metadata);
        assert!(
            !should_update_minor,
            "Should block minor updates with PatchOnly policy"
        );
    }

    #[test]
    fn test_should_auto_update_minor_and_patch() {
        let analyzer = create_test_analyzer();
        let policy = create_test_policy(UpdateLevel::MinorAndPatch);
        let current = Version::new(1, 2, 3);

        let minor_update = Version::new(1, 3, 0);
        let metadata = analyzer
            .analyze_release_notes("- Add new feature", "1.3.0")
            .unwrap();

        let should_update =
            analyzer.should_auto_update(&policy, &current, &minor_update, &metadata);
        assert!(
            should_update,
            "Should allow minor updates with MinorAndPatch policy"
        );

        let major_update = Version::new(2, 0, 0);
        let major_metadata = analyzer
            .analyze_release_notes("- Major version release", "2.0.0")
            .unwrap();

        let should_update_major =
            analyzer.should_auto_update(&policy, &current, &major_update, &major_metadata);
        assert!(
            !should_update_major,
            "Should block major updates with MinorAndPatch policy"
        );
    }

    #[test]
    fn test_should_auto_update_security_override() {
        let analyzer = create_test_analyzer();
        let policy = create_test_policy(UpdateLevel::PatchOnly);
        let current = Version::new(1, 2, 3);

        let security_minor = Version::new(1, 3, 0);
        let security_metadata = analyzer
            .analyze_release_notes("- Security fix for vulnerability", "1.3.0")
            .unwrap();

        let should_update =
            analyzer.should_auto_update(&policy, &current, &security_minor, &security_metadata);
        assert!(
            should_update,
            "Should allow security updates even if they exceed policy level"
        );
    }

    #[test]
    fn test_should_not_auto_update_downgrades() {
        let analyzer = create_test_analyzer();
        let policy = create_test_policy(UpdateLevel::All);
        let current = Version::new(1, 2, 3);

        let downgrade = Version::new(1, 2, 2);
        let metadata = analyzer
            .analyze_release_notes("- Rollback release", "1.2.2")
            .unwrap();

        let should_update = analyzer.should_auto_update(&policy, &current, &downgrade, &metadata);
        assert!(!should_update, "Should never allow downgrades");
    }

    #[test]
    fn test_should_not_auto_update_breaking_changes() {
        let analyzer = create_test_analyzer();
        let policy = create_test_policy(UpdateLevel::All);
        let current = Version::new(1, 2, 3);

        let breaking_update = Version::new(2, 0, 0);
        let breaking_metadata = analyzer
            .analyze_release_notes("💥 Breaking: Remove old API", "2.0.0")
            .unwrap();

        let should_update =
            analyzer.should_auto_update(&policy, &current, &breaking_update, &breaking_metadata);
        assert!(
            !should_update,
            "Should block breaking changes even with All policy"
        );
    }

    #[test]
    fn test_analyze_invalid_version() {
        let analyzer = create_test_analyzer();

        let result = analyzer.analyze_release_notes("Some release notes", "not-a-version");
        assert!(result.is_err(), "Should fail with invalid version string");
    }

    #[test]
    fn test_has_breaking_changes_by_version() {
        let analyzer = create_test_analyzer();

        let v1_2_3 = Version::new(1, 2, 3);
        let v1_2_4 = Version::new(1, 2, 4);
        let v1_3_0 = Version::new(1, 3, 0);
        let v2_0_0 = Version::new(2, 0, 0);

        assert!(
            !analyzer.has_breaking_changes(&v1_2_3, &v1_2_4),
            "Patch updates should not be breaking"
        );
        assert!(
            !analyzer.has_breaking_changes(&v1_2_3, &v1_3_0),
            "Minor updates should not be breaking"
        );
        assert!(
            analyzer.has_breaking_changes(&v1_2_3, &v2_0_0),
            "Major updates should be breaking"
        );
    }
}
