# Security Report — FlaskDataService

- Generated: 2026-07-28T00:24:40Z
- Engine: Trivy (SBOM scan)

## Summary

| Critical | High | Medium | Low | Unknown | Total |
|---:|---:|---:|---:|---:|---:|
| 0 | 6 | 13 | 1 | 0 | 20 |

- Actively exploited (CISA KEV): **0**
- Priority order: KEV first, then severity, then EPSS (exploit probability).

## Findings

| Severity | KEV | CVSS | EPSS | CVE | Package | Installed | Fixed |
|----------|-----|-----:|-----:|-----|---------|-----------|-------|
| HIGH |  | 7.5 | 0.033 | CVE-2024-34069 | Werkzeug | 3.0.1 | 3.0.3 |
| HIGH |  | 7.5 | 0.026 | CVE-2026-21441 | urllib3 | 2.1.0 | 2.6.3 |
| HIGH |  | 7.5 | 0.006 | CVE-2025-66418 | urllib3 | 2.1.0 | 2.6.0 |
| HIGH |  | 7.5 | 0.006 | CVE-2025-66471 | urllib3 | 2.1.0 | 2.6.0 |
| HIGH |  | 7.5 | 0.005 | CVE-2026-32274 | black | 23.12.1 | 26.3.1 |
| HIGH |  | 5.9 | 0.003 | CVE-2026-44431 | urllib3 | 2.1.0 | 2.7.0 |
| MEDIUM |  | 6.5 | 0.011 | CVE-2024-37891 | urllib3 | 2.1.0 | 1.26.19, 2.2.2 |
| MEDIUM |  | 7.5 | 0.011 | CVE-2024-49767 | Werkzeug | 3.0.1 | 3.0.6 |
| MEDIUM |  | 5.3 | 0.009 | CVE-2024-21503 | black | 23.12.1 | 24.3.0 |
| MEDIUM |  | 5.3 | 0.008 | CVE-2024-47081 | requests | 2.31.0 | 2.32.4 |
| MEDIUM |  | 5.3 | 0.007 | CVE-2024-49766 | Werkzeug | 3.0.1 | 3.0.6 |
| MEDIUM |  | 5.3 | 0.005 | CVE-2026-27199 | Werkzeug | 3.0.1 | 3.1.6 |
| MEDIUM |  | 5.3 | 0.005 | CVE-2025-66221 | Werkzeug | 3.0.1 | 3.1.4 |
| MEDIUM |  | 5.3 | 0.004 | CVE-2026-21860 | Werkzeug | 3.0.1 | 3.1.5 |
| MEDIUM |  | 6.1 | 0.003 | CVE-2025-50181 | urllib3 | 2.1.0 | 2.5.0 |
| MEDIUM |  | 5.6 | 0.003 | CVE-2024-35195 | requests | 2.31.0 | 2.32.0 |
| MEDIUM |  | 7.1 | 0.002 | CVE-2026-28684 | python-dotenv | 1.0.0 | 1.2.2 |
| MEDIUM |  | 5.5 | 0.001 | CVE-2026-25645 | requests | 2.31.0 | 2.33.0 |
| MEDIUM |  | 6.8 | 0.001 | CVE-2025-71176 | pytest | 7.4.3 | 9.0.3 |
| LOW |  | 4.3 | 0.003 | CVE-2026-27205 | Flask | 3.0.0 | 3.1.3 |
