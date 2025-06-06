# Security Policy

## Supported Versions

Currently, only the latest version of DNSPX is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Known Security Considerations

### RSA Marvin Attack (Windows Only)

**Affected Component:** Windows SSPI Authentication  
**Severity:** Medium (CVSS 5.9)  
**CVE Reference:** RUSTSEC-2023-0071

#### Description
DNSPX's Windows SSPI authentication feature uses the `rsa` crate (v0.9.8) which is vulnerable to the Marvin Attack - a timing side-channel attack that could potentially allow key recovery.

#### Impact
- **Affected Platforms:** Windows only
- **Prerequisites for Attack:**
  - Windows system using SSPI proxy authentication
  - Local attacker with ability to measure precise timing
  - Specific network conditions enabling timing analysis
- **Risk Level:** Low to Medium (requires sophisticated local attack setup)

#### Mitigation Strategies
1. **Disable SSPI Authentication:** Use alternative proxy authentication methods (Basic Auth) when possible
2. **Network Isolation:** Ensure DNSPX runs in isolated network environments
3. **Monitoring:** Monitor for unusual network timing patterns
4. **Updates:** Monitor for updates to the `sspi` crate that address this issue

#### Technical Details
```
Dependency Path:
rsa v0.9.8
└── picky v7.0.0-rc.14
    └── sspi v0.10.1 (Windows only)
        └── dnspx v0.9.0
```

**Note:** This vulnerability only affects Windows builds when SSPI authentication is explicitly configured and used. Linux and macOS builds are not affected.

### Unmaintained Dependencies

The following dependencies have maintenance warnings but pose minimal security risk:

- **atty v0.2.14** - Used for terminal detection, low risk
- **paste v1.0.15** - Macro helper for ratatui, minimal exposure

## Production Deployment Recommendations

### Windows Environments
- Thoroughly test SSPI authentication in your specific environment
- Consider using Basic authentication instead of SSPI for production deployments
- Implement network monitoring for unusual patterns
- Keep systems updated and monitor for dependency updates

### AWS Integration
- AWS service discovery features should be thoroughly tested before production use
- Use least-privilege IAM roles for AWS integration
- Monitor AWS API usage patterns
- Validate discovered AWS resources before relying on them

### General Security
- Run DNSPX with minimal required privileges
- Use network firewalls to restrict access to DNS port (53)
- Monitor DNS query patterns for anomalies
- Regularly update to latest versions
- Review configuration files for security best practices

## Reporting a Vulnerability

If you discover a security vulnerability in DNSPX:

1. **Do not** create a public GitHub issue
2. Email the maintainer privately (if available) or
3. Create a private security advisory on GitHub
4. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested mitigation (if any)

### Response Timeline
- **Initial Response:** Within 72 hours
- **Vulnerability Assessment:** Within 1 week
- **Fix Timeline:** Depends on severity and complexity

### Disclosure Policy
We follow responsible disclosure practices:
- Confirmed vulnerabilities will be patched before public disclosure
- Security advisories will be published after fixes are available
- Credit will be given to security researchers who report vulnerabilities responsibly

## Security Best Practices

### Configuration Security
- Store configuration files with appropriate file permissions (600 or similar)
- Avoid storing sensitive credentials in configuration files
- Use environment variables or secure credential stores when possible
- Regularly review and audit configuration settings

### Network Security
- Bind to specific interfaces rather than 0.0.0.0 when possible
- Use firewall rules to restrict access to the DNS port
- Consider using encrypted DNS (DoH/DoT) for upstream resolvers
- Monitor network traffic patterns

### Operational Security
- Run DNSPX with dedicated service accounts with minimal privileges
- Implement log monitoring and alerting
- Regular security reviews of deployment configuration
- Keep underlying system and dependencies updated

For questions about security practices or this policy, please reach out through the appropriate channels.