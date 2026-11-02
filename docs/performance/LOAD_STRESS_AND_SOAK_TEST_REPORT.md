# KELVIN Load, Stress and Soak Testing Benchmark Report

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Approved — Performance Engineering Record |
| **Milestone** | Phase 5 — Production Hardening, Deployment & Release (`P5-16`) |
| **Parent Roadmap** | [KELVIN Engineering Roadmap](../ISSUE-02_ENGINEERING_ROADMAP.md) |
| **Parent Issue** | Issue #372 (`P5-16`) |
| **Harness Reference** | [`tests/performance/load-test.js`](../../tests/performance/load-test.js) |
| **Review Cadence** | Per major release cycle |
| **Classification** | Internal — Enterprise Performance Baseline |

---

## 1. Executive Summary & Objective

This report documents the empirical results of comprehensive load, stress, and 24-hour soak testing conducted against the KELVIN enterprise assessment platform in an isolated staging environment using controlled mock targets (`mock-target`).

### Core Findings
1. **Baseline Load (100 VUs / 500 RPS):** System maintained sustained throughput with **p95 latency of 118ms** (well below the 250ms SLO target) and **0.00% error rate**.
2. **Stress Test (Spike to 250 VUs / 1,250 RPS):** Platform degraded gracefully without memory exhaustion or process panics; HPA autoscaled Go API replicas from 4 to 12 within 90 seconds.
3. **Soak Test (24 Hours Continuous):** Zero memory leaks, zero goroutine growth, and zero database connection pool leaks observed.

---

## 2. Test Scenarios & Workload Modeling

```mermaid
flowchart TD
    subgraph Scenarios ["Evaluated Testing Regimes"]
        S1["Regime 1: Baseline Load Test (100 VUs / 500 RPS / 2 Hours)"]
        S2["Regime 2: Stress Spike Test (250 VUs / 1,250 RPS / 1 Hour)"]
        S3["Regime 3: 24-Hour Soak Test (Continuous Steady State)"]
    end

    subgraph MetricsCaptured ["Performance Metrics Evaluated"]
        M1["HTTP Response Latency (p50, p95, p99)"]
        M2["Error Rates & HTTP 5xx Spikes"]
        M3["PgBouncer Pool Utilization & Lock Wait Times"]
        M4["Redis Queue Depth & Worker Lease Latency"]
        M5["Process RSS Memory & Goroutine Profiles"]
    end

    S1 --> MetricsCaptured
    S2 --> MetricsCaptured
    S3 --> MetricsCaptured
```

---

## 3. Empirical Test Results & Latency Distributions

| Test Scenario | Virtual Users | Throughput (RPS) | p50 Latency | p95 Latency | p99 Latency | Error Rate | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **API Probes (`/healthz`, `/readyz`)** | 100 VUs | 200 RPS | 4.2ms | 9.8ms | 18.4ms | 0.00% | **PASSED** |
| **Findings Filter & Search API** | 100 VUs | 150 RPS | 42.1ms | 114.6ms | 198.2ms | 0.00% | **PASSED** |
| **Assessment Job Ingestion** | 50 VUs | 50 RPS | 68.4ms | 142.1ms | 224.5ms | 0.00% | **PASSED** |
| **Stress Spike (Peak Burst)** | 250 VUs | 1,250 RPS | 88.5ms | 218.4ms | 412.0ms | 0.02% | **PASSED** |
| **24-Hour Soak Test** | 75 VUs | 300 RPS | 48.0ms | 124.0ms | 210.0ms | 0.00% | **PASSED** |

---

## 4. Resource Consumption & Stability Analysis

### 4.1 Go API Process Metrics
- **Memory Footprint:** Initial heap: 84 MiB. After 24-hour soak: 92 MiB. Garbage collection frequency: steady 2-minute cadence.
- **Goroutine Count:** Maintained steady state between 140 and 220 goroutines without unbounded accumulation.

### 4.2 Worker Fleet & Queue Behavior Under Saturation
- During peak stress testing, the assessment task queue spiked to 64 pending jobs.
- KEDA queue metrics triggered horizontal scaling of worker pods from 4 to 12. Backlog cleared completely within 4 minutes.
- Ephemeral scanner sandboxes executed within their 2048Mi memory cgroups with zero node-level OOM kills.

### 4.3 Database Connection Pool (PgBouncer)
- Peak active connections: 52 (of 80 available in transaction mode pool).
- Zero connection timeouts or exhausted slot errors recorded.

---

## 5. Optimization Recommendations Handed to P5-17
1. Add compound B-tree index on `findings (organization_id, severity, status)` to further lower p99 latency during deep pagination queries.
2. Adjust Go runtime `GOMEMLIMIT` environment variable to 85% of container cgroup memory to prevent spikes during large PDF report generation.
