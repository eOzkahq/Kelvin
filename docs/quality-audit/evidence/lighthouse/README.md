# Quality Audit Evidence — Lighthouse & Performance Benchmarks

This directory contains automated Google Lighthouse runs, Core Web Vitals traces, and asset bundle analyses.

## Summary Benchmarks
- **Lighthouse Performance Score:** 96 / 100
- **Lighthouse Accessibility Score:** 100 / 100
- **Lighthouse Best Practices Score:** 100 / 100
- **Lighthouse SEO Score:** 100 / 100

## Artifact Inventory
- `bundle-analysis.json`: Vite build chunk breakdown verifying main JS payload of 94.47 kB gzipped.
- `lighthouse-report-findings.json`: Lighthouse audit report for `/findings` workspace under simulated 4G mobile throttling.
- `core-web-vitals-summary.json`: LCP (1.12s), INP (48ms), CLS (0.008) measurements across 500 benchmark iterations.
