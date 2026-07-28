# Supplier SBOM risk report — FlaskDataService

- Generated: 2026-07-28T00:24:51Z
- This report re-aggregates the vulnerability and license artifacts already produced, without running a new scan.

## 1. Requirements met (format validation)

- Input format: CycloneDX
- Validation result: **PASS**

## 2. Vulnerability analysis and remediation deadlines

> Recommended remediation deadlines: **Critical → within 7 days, High → within 30 days**. We recommend preparing a remediation plan or risk justification.

| Critical | High | Medium | Low | Unknown | Total |
|---:|---:|---:|---:|---:|---:|
| 0 | 6 | 13 | 1 | 0 | 20 |

| Severity | CVE | Package | Installed | Fixed | Deadline |
|----------|-----|---------|-----------|-------|-----------|
| HIGH | CVE-2024-34069 | Werkzeug | 3.0.1 | 3.0.3 | within 30 days |
| HIGH | CVE-2026-32274 | black | 23.12.1 | 26.3.1 | within 30 days |
| HIGH | CVE-2025-66418 | urllib3 | 2.1.0 | 2.6.0 | within 30 days |
| HIGH | CVE-2025-66471 | urllib3 | 2.1.0 | 2.6.0 | within 30 days |
| HIGH | CVE-2026-21441 | urllib3 | 2.1.0 | 2.6.3 | within 30 days |
| HIGH | CVE-2026-44431 | urllib3 | 2.1.0 | 2.7.0 | within 30 days |
| MEDIUM | CVE-2024-49766 | Werkzeug | 3.0.1 | 3.0.6 | Per policy |
| MEDIUM | CVE-2024-49767 | Werkzeug | 3.0.1 | 3.0.6 | Per policy |
| MEDIUM | CVE-2025-66221 | Werkzeug | 3.0.1 | 3.1.4 | Per policy |
| MEDIUM | CVE-2026-21860 | Werkzeug | 3.0.1 | 3.1.5 | Per policy |
| MEDIUM | CVE-2026-27199 | Werkzeug | 3.0.1 | 3.1.6 | Per policy |
| MEDIUM | CVE-2024-21503 | black | 23.12.1 | 24.3.0 | Per policy |
| MEDIUM | CVE-2025-71176 | pytest | 7.4.3 | 9.0.3 | Per policy |
| MEDIUM | CVE-2026-28684 | python-dotenv | 1.0.0 | 1.2.2 | Per policy |
| MEDIUM | CVE-2024-35195 | requests | 2.31.0 | 2.32.0 | Per policy |
| MEDIUM | CVE-2024-47081 | requests | 2.31.0 | 2.32.4 | Per policy |
| MEDIUM | CVE-2026-25645 | requests | 2.31.0 | 2.33.0 | Per policy |
| MEDIUM | CVE-2024-37891 | urllib3 | 2.1.0 | 1.26.19, 2.2.2 | Per policy |
| MEDIUM | CVE-2025-50181 | urllib3 | 2.1.0 | 2.5.0 | Per policy |
| LOW | CVE-2026-27205 | Flask | 3.0.0 | 3.1.3 | Per policy |

## 3. License summary

- Distinct licenses identified: 10 (see `FlaskDataService_3.2.0_NOTICE.{txt,html}` for details)

### License classification (copyleft strength)

Each component is also recorded in the SBOM with a `bomlens:licenseClass` property. An unrecognized license is left uncategorized rather than assumed permissive.

| Network copyleft | Strong copyleft | Weak copyleft | Permissive | Uncategorized |
|---:|---:|---:|---:|---:|
| 0 | 0 | 2 | 33 | 4 |

## 4. Next steps

1. Prepare a **remediation plan or risk justification** within the recommended deadlines above.
2. If format validation failed, fill the missing items and regenerate the SBOM.
