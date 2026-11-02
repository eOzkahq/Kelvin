# Quality Audit Evidence — Accessibility & Assistive Technology Traces

This directory contains automated axe-core audit scans, contrast analysis logs, and screen reader output transcripts for WCAG 2.2 Level AA compliance.

## Summary Results
- **axe-core Violations:** 0 Critical, 0 Serious, 0 Moderate
- **Normal Text Contrast Ratio:** 9.81 : 1 (Minimum standard: 4.5 : 1)
- **UI Non-Text Contrast Ratio:** 3.65 : 1 (Minimum standard: 3.0 : 1)
- **Keyboard Tab Traps:** 0 Traps

## Artifact Inventory
- `axe-core-scan-results.json`: Automated axe-core sweep across all 5 registered web application routes.
- `aud-002-aria-expanded.txt`: DOM tree accessibility state trace verifying `aria-expanded` toggle on navigation controls.
- `aud-003-contrast.json`: Spectral color contrast analysis logs for dark mode table cell borders.
- `screen-reader-transcript-nvda.txt`: NVDA voice announcement logs covering User Journey UJ-05 (Findings Search & Detail Drawer).
