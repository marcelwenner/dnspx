# DNSPX Release Notes

## Version 0.9.0 - Initial Public Release

We are excited to announce the initial public release of **DNSPX version 0.9.0**!

DNSPX is a versatile DNS proxy and resolver designed to provide flexible DNS management for local development, testing, and integration with cloud environments, particularly AWS. This initial release lays the foundation with a robust set of core features.

### New Features & Key Capabilities

#### Core DNS Functionality
*   **DNS Proxy Engine:**
    *   Supports forwarding DNS queries over **UDP** and **TCP**.
    *   Listens on a configurable IP address and port (default `0.0.0.0:53`).
*   **Upstream Resolver Support:**
    *   **Standard DNS:** Can forward queries to traditional DNS servers (e.g., `8.8.8.8:53`).
    *   **DNS-over-HTTPS (DoH):** Supports DoH endpoints (e.g., `https://cloudflare-dns.com/dns-query`) for secure upstream resolution.
    *   Configurable timeout for upstream queries.
*   **Resolver Strategies:**
    *   Flexible strategies for selecting an upstream resolver when multiple are configured:
        *   `First`: Tries servers in the order listed.
        *   `Random`: Selects a server randomly.
        *   `Rotate`: Cycles through servers sequentially.
        *   `Fastest`: (Implementation might be basic in 0.9.0, potential for future enhancement) Aims to pick the quickest responder.
*   **DNS Caching:**
    *   In-memory caching of DNS responses to improve performance and reduce upstream load.
    *   Configurable `max_capacity` for the cache.
    *   Adjustable `min_ttl` and `max_ttl` to control how long entries are cached.
    *   Option to `serve_stale_if_error`: If an upstream query fails, a stale cache entry (within `serve_stale_max_ttl`) can be served.
*   **Rule-Based Routing Engine:**
    *   Define rules based on domain name regular expression patterns (`domain_pattern`).
    *   Supported rule actions:
        *   `Forward`: Route matching queries to specific upstream `nameservers` (standard DNS or DoH) with a custom `strategy` and `timeout`.
        *   `Block`: Respond with `NXDomain` for matching queries.
        *   `Allow`: Explicitly permit a query to proceed to the default resolver (useful for overriding broader block rules).
        *   `ResolveLocal`: Attempt to resolve matching queries using the local hosts configuration.
    *   `invert_match` option for rules to apply to domains *not* matching the pattern.
*   **Local Hosts Resolution:**
    *   Define custom DNS records in the configuration file (`local_hosts.entries`) for local development or overrides.
    *   Supports A, AAAA, and PTR record resolution from local hosts.

#### AWS Integration
*   **AWS Service Discovery (Initial Support):**
    *   Ability to discover various AWS resources and automatically make them resolvable via DNSPX.
    *   Configured per AWS account using AWS CLI profiles.
    *   Supports discovering:
        *   Generic VPC Endpoints (Interface Endpoints) and their private IP addresses.
        *   Private API Gateways.
        *   RDS Instances.
        *   ElastiCache Clusters (configuration and node endpoints).
        *   DocumentDB Clusters (cluster and reader endpoints).
        *   Running/Pending EC2 Instances and their private DNS names/IPs.
    *   Discovered entries are added to the internal DNS cache with a configurable TTL.
*   **AWS Authentication:**
    *   Utilizes AWS SDK for credential loading via profiles.
    *   Supports MFA token input (via console prompt in TUI mode) when required by profiles.
    *   Supports IAM Role Assumption for cross-account scanning scenarios.
*   **VPC-Aware DNS Resolution:**
    *   Discovers Route 53 Inbound Resolver Endpoints. These IPs can then be used internally by the AWS scanner to resolve service DNS names as they would resolve within the VPC.
    *   Discovers Private Hosted Zones associated with specified VPCs.
*   **Configuration & Management:**
    *   Periodic rescanning of AWS resources based on `scan_interval`.
    *   AWS credential caching to reduce STS calls.
    *   Option to output a proxy bypass list (`output_file_name`) for discovered AWS service domains.

#### Management & Monitoring
*   **Text User Interface (TUI) (`--tui` flag):**
    *   **Dashboard View:** Real-time display of application status, uptime, query statistics (total queries, QPS), cache statistics (size, hits, misses), active listeners, and configuration status.
    *   **AWS Scanner View:** Detailed status of the AWS discovery process, including scan progress, last scan time, discovered entries count, accounts scanned/failed, and any errors.
    *   **Log Viewer Panel:** Live stream of application logs within the TUI, with adjustable filter levels (Trace, Debug, Info, Warn, Error, All). Supports scrolling and follow-mode.
    *   **DNS Cache Viewer:** Interactive table display of current DNS cache entries. Shows domain name, type, remaining TTL, and value. Supports filtering, scrolling, and manual addition/deletion of synthetic cache entries.
    *   **Hotkey Panel & Help Popup:** Provides guidance on available keyboard shortcuts.
*   **Command Line Interface (CLI) (`--cli-only` flag):**
    *   Basic interactive mode for status checks, configuration reloads, and triggering AWS scans.
*   **Query Logging:** Optional feature to log details of each DNS query processed.

#### Configuration
*   **TOML-Based Configuration:** Primary configuration through a single `dnspx_config.toml` file.
*   **Automatic Configuration Reload:** DNSPX monitors the configuration file for changes and reloads it automatically, applying new settings where possible without a full restart.
*   **Legacy Configuration Migration:** Support for migrating from older JSON-based `config.json`, `rules.json`, and `hosts.json` files to the new TOML format. Backups of old files are created during migration.
*   **Command-line Arguments:**
    *   `--config <path>`: Specify a custom path to the configuration file.
    *   `--tui`: Launch the Text User Interface.
    *   `--cli-only`: Run without the TUI dashboard.

### Supported DNS Record Types (for Caching & Local Hosts)
*   A
*   AAAA
*   CNAME
*   TXT
*   MX (basic RData formatting in Cache Viewer)
*   SOA (basic RData formatting in Cache Viewer, used for NXDomain caching TTL)
*   PTR (for local hosts reverse resolution)

### Build & Testing
*   Builds with Rust 1.70 and later.
*   Includes a shell script (`test/dns-proxy-test.sh`) for basic functional and performance testing.

### Known Issues & Limitations (Version 0.9.0)
*   The "Fastest" resolver strategy is basic and may not always pick the true fastest resolver under all network conditions.
*   File-based local hosts (`local_hosts.file_path` and `watch_file`) is not fully implemented for parsing standard hosts file formats; currently relies on direct `entries` in TOML.
*   AWS Service Discovery for some less common or very new service endpoint types might not be included yet.
*   TUI prompts for MFA/AWS Keys currently fall back to console input rather than an in-TUI modal.
*   Performance under extremely high query loads (thousands of QPS) has not been extensively benchmarked.


### Future Enhancements (Roadmap beyond 0.9.0)
*   DNS-over-TLS (DoT) support for upstream resolvers.
*   Enhanced rule conditions (e.g., client IP source).
*   Metrics endpoint for Prometheus/Grafana.
*   Support for other cloud providers (Azure, GCP).
*   Persistent cache options.

We encourage users to try out DNSPX and provide feedback, report bugs, or contribute to its development. Please visit our [GitHub repository](https://github.com/marcelwenner/dnspx) for more information.
