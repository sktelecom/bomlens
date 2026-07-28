# Open-source risk analysis report — SpringBootDemo

- Generated: 2026-07-28T00:09:24Z
- This report re-aggregates the vulnerability and license artifacts already produced, without running a new scan.

## 1. Vulnerability analysis and remediation deadlines

> Recommended remediation deadlines: **Critical → within 7 days, High → within 30 days**. We recommend preparing a remediation plan or risk justification.

| Critical | High | Medium | Low | Unknown | Total |
|---:|---:|---:|---:|---:|---:|
| 4 | 27 | 22 | 12 | 0 | 65 |

| Severity | CVE | Package | Installed | Fixed | Deadline |
|----------|-----|---------|-----------|-------|-----------|
| CRITICAL | CVE-2025-24813 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.3, 10.1.35, 9.0.99 | within 7 days |
| CRITICAL | CVE-2026-41293 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | within 7 days |
| CRITICAL | CVE-2026-43512 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | within 7 days |
| CRITICAL | CVE-2026-43515 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | within 7 days |
| HIGH | CVE-2023-6378 | ch.qos.logback:logback-classic | 1.4.11 | 1.3.12, 1.4.12, 1.2.13 | within 30 days |
| HIGH | CVE-2023-6378 | ch.qos.logback:logback-core | 1.4.11 | 1.3.12, 1.4.12, 1.2.13 | within 30 days |
| HIGH | GHSA-r7wm-3cxj-wff9 | com.fasterxml.jackson.core:jackson-core | 2.16.0 | 2.18.8, 2.21.4, 2.22.1 | within 30 days |
| HIGH | CVE-2026-54512 | com.fasterxml.jackson.core:jackson-databind | 2.16.0 | 2.18.8, 3.1.4, 2.21.4 | within 30 days |
| HIGH | CVE-2026-54513 | com.fasterxml.jackson.core:jackson-databind | 2.16.0 | 2.18.8, 2.21.4, 3.1.4 | within 30 days |
| HIGH | CVE-2024-34750 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.0-M21, 10.1.25, 9.0.90 | within 30 days |
| HIGH | CVE-2024-38286 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.0-M21, 10.1.25, 9.0.90 | within 30 days |
| HIGH | CVE-2024-50379 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.2, 10.1.34, 9.0.98 | within 30 days |
| HIGH | CVE-2024-56337 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.2, 10.1.34, 9.0.98 | within 30 days |
| HIGH | CVE-2025-48988 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.8, 10.1.42, 9.0.106 | within 30 days |
| HIGH | CVE-2025-48989 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.10, 10.1.44, 9.0.108 | within 30 days |
| HIGH | CVE-2025-52520 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.9, 10.1.43, 9.0.107 | within 30 days |
| HIGH | CVE-2025-53506 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.107, 10.1.43, 11.0.9 | within 30 days |
| HIGH | CVE-2025-55752 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.11, 10.1.45, 9.0.109 | within 30 days |
| HIGH | CVE-2026-24734 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.18, 10.1.52, 9.0.115 | within 30 days |
| HIGH | CVE-2026-24880 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.116, 10.1.52, 11.0.20 | within 30 days |
| HIGH | CVE-2026-34483 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.116, 10.1.54, 11.0.21 | within 30 days |
| HIGH | CVE-2026-41284 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | within 30 days |
| HIGH | CVE-2026-42498 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | within 30 days |
| HIGH | CVE-2026-43513 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | within 30 days |
| HIGH | CVE-2025-22235 | org.springframework.boot:spring-boot | 3.2.0 | 3.3.11, 3.4.5 | within 30 days |
| HIGH | CVE-2025-41249 | org.springframework:spring-core | 6.1.1 | 6.2.11 | within 30 days |
| HIGH | CVE-2024-22243 | org.springframework:spring-web | 6.1.1 | 6.1.4, 6.0.17, 5.3.32 | within 30 days |
| HIGH | CVE-2024-22259 | org.springframework:spring-web | 6.1.1 | 6.1.5, 6.0.18, 5.3.33 | within 30 days |
| HIGH | CVE-2024-22262 | org.springframework:spring-web | 6.1.1 | 5.3.34, 6.0.19, 6.1.6 | within 30 days |
| HIGH | CVE-2024-38816 | org.springframework:spring-webmvc | 6.1.1 | 6.1.13 | within 30 days |
| HIGH | CVE-2024-38819 | org.springframework:spring-webmvc | 6.1.1 | 6.1.14 | within 30 days |
| MEDIUM | CVE-2024-12798 | ch.qos.logback:logback-core | 1.4.11 | 1.5.13, 1.3.15 | Per policy |
| MEDIUM | CVE-2025-11226 | ch.qos.logback:logback-core | 1.4.11 | 1.5.19, 1.3.16 | Per policy |
| MEDIUM | GHSA-72hv-8253-57qq | com.fasterxml.jackson.core:jackson-core | 2.16.0 | 2.21.1, 2.18.6 | Per policy |
| MEDIUM | CVE-2026-54514 | com.fasterxml.jackson.core:jackson-databind | 2.16.0 | 2.18.8, 2.21.4, 3.1.4 | Per policy |
| MEDIUM | CVE-2026-54515 | com.fasterxml.jackson.core:jackson-databind | 2.16.0 | 3.1.4, 2.18.9, 2.21.5, 2.22.1 | Per policy |
| MEDIUM | CVE-2026-59888 | com.fasterxml.jackson.core:jackson-databind | 2.16.0 | 2.18.8, 2.21.4 | Per policy |
| MEDIUM | CVE-2025-48924 | org.apache.commons:commons-lang3 | 3.14.0 | 3.18.0 | Per policy |
| MEDIUM | CVE-2024-24549 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 8.5.99, 9.0.86, 10.1.19, 11.0.0-M17 | Per policy |
| MEDIUM | CVE-2025-31650 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.104, 10.1.40, 11.0.6 | Per policy |
| MEDIUM | CVE-2025-49124 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.8, 10.1.42, 9.0.106 | Per policy |
| MEDIUM | CVE-2025-49125 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.8, 10.1.42, 9.0.106 | Per policy |
| MEDIUM | CVE-2025-55668 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.8, 10.1.42, 9.0.106 | Per policy |
| MEDIUM | CVE-2025-66614 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.15, 10.1.50, 9.0.113 | Per policy |
| MEDIUM | CVE-2026-25854 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.116, 10.1.53, 11.0.20 | Per policy |
| MEDIUM | CVE-2024-23672 | org.apache.tomcat.embed:tomcat-embed-websocket | 10.1.16 | 11.0.0-M17, 10.1.19, 9.0.86, 8.5.99 | Per policy |
| MEDIUM | CVE-2024-38820 | org.springframework:spring-context | 6.1.1 | 6.1.14 | Per policy |
| MEDIUM | CVE-2024-38809 | org.springframework:spring-web | 6.1.1 | 5.3.38, 6.0.23, 6.1.12 | Per policy |
| MEDIUM | CVE-2024-38820 | org.springframework:spring-web | 6.1.1 | 6.1.14 | Per policy |
| MEDIUM | CVE-2025-41234 | org.springframework:spring-web | 6.1.1 | 6.2.8, 6.1.21 | Per policy |
| MEDIUM | CVE-2025-41242 | org.springframework:spring-webmvc | 6.1.1 | 6.2.10 | Per policy |
| MEDIUM | CVE-2026-22737 | org.springframework:spring-webmvc | 6.1.1 | 7.0.6, 6.2.17 | Per policy |
| MEDIUM | CVE-2026-22745 | org.springframework:spring-webmvc | 6.1.1 | 7.0.7, 6.2.18 | Per policy |
| LOW | CVE-2024-12801 | ch.qos.logback:logback-core | 1.4.11 | 1.5.13, 1.3.15 | Per policy |
| LOW | CVE-2026-10532 | ch.qos.logback:logback-core | 1.4.11 | 1.5.34 | Per policy |
| LOW | CVE-2026-1225 | ch.qos.logback:logback-core | 1.4.11 | 1.5.25 | Per policy |
| LOW | CVE-2026-9828 | ch.qos.logback:logback-core | 1.4.11 | 1.5.33 | Per policy |
| LOW | CVE-2025-31651 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.104, 10.1.40, 11.0.6 | Per policy |
| LOW | CVE-2025-46701 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.105, 10.1.41, 11.0.7 | Per policy |
| LOW | CVE-2025-55754 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.11, 10.1.45, 9.0.109 | Per policy |
| LOW | CVE-2025-61795 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 11.0.12, 10.1.47, 9.0.110 | Per policy |
| LOW | CVE-2026-43514 | org.apache.tomcat.embed:tomcat-embed-core | 10.1.16 | 9.0.118, 10.1.55, 11.0.22 | Per policy |
| LOW | CVE-2025-22233 | org.springframework:spring-context | 6.1.1 | 6.2.7, 6.1.20 | Per policy |
| LOW | CVE-2026-22735 | org.springframework:spring-webmvc | 6.1.1 | 7.0.6, 6.2.17 | Per policy |
| LOW | CVE-2026-22741 | org.springframework:spring-webmvc | 6.1.1 | 7.0.7, 6.2.18 | Per policy |

## 2. License summary

- Distinct licenses identified: 13 (see `SpringBootDemo_1.0.0_NOTICE.{txt,html}` for details)

### License classification (copyleft strength)

Each component is also recorded in the SBOM with a `bomlens:licenseClass` property. An unrecognized license is left uncategorized rather than assumed permissive.

| Network copyleft | Strong copyleft | Weak copyleft | Permissive | Uncategorized |
|---:|---:|---:|---:|---:|
| 0 | 2 | 6 | 55 | 8 |

Components that create copyleft exposure (network/strong, up to 10):

- `jakarta.annotation-api@2.1.1` (strong-copyleft)
- `jakarta.transaction-api@2.0.1` (strong-copyleft)

## 3. Next steps

1. Prepare a **remediation plan or risk justification** within the recommended deadlines above.
2. Keep and distribute the notice (`SpringBootDemo_1.0.0_NOTICE.{txt,html}`) together with the SBOM (`SpringBootDemo_1.0.0_bom.json`).
