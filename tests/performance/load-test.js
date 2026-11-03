// KELVIN Enterprise Performance & Load Test Suite (k6)
// Targets: Isolated Staging & Local Mock Targets only
import http from 'k6/http';
import { check, sleep, group } from 'k6';

export const options = {
  scenarios: {
    // 1. Baseline Load Test: 100 concurrent VUs for 5 minutes
    baseline_load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 50 },
        { duration: '3m', target: 100 },
        { duration: '1m', target: 0 },
      ],
      gracefulRampDown: '30s',
    },
    // 2. Stress Test Spike: Peak burst to 250 VUs
    stress_spike: {
      executor: 'ramping-vus',
      startTime: '5m30s',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 250 },
        { duration: '2m', target: 250 },
        { duration: '1m', target: 0 },
      ],
      gracefulRampDown: '30s',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<250', 'p(99)<1000'], // 95% of requests under 250ms
    http_req_failed: ['rate<0.01'],                  // Error rate < 1%
  },
};

const BASE_URL = __ENV.API_BASE_URL || 'http://localhost:8080';

export default function () {
  const headers = {
    'Content-Type': 'application/json',
    'X-Correlation-ID': `perf-${__VU}-${__ITER}`,
  };

  group('Health & Readiness Probes', () => {
    const res = http.get(`${BASE_URL}/healthz`, { headers });
    check(res, { 'healthz is 200': (r) => r.status === 200 });

    const readyRes = http.get(`${BASE_URL}/readyz`, { headers });
    check(readyRes, { 'readyz is 200': (r) => r.status === 200 });
  });

  group('Findings Search & Filter API', () => {
    const res = http.get(`${BASE_URL}/api/v1/findings?limit=50&severity=HIGH`, { headers });
    check(res, {
      'findings response status ok or auth': (r) => r.status === 200 || r.status === 401,
      'duration under 250ms': (r) => r.timings.duration < 250,
    });
  });

  group('Assessment Creation API', () => {
    const payload = JSON.stringify({
      target_url: 'http://mock-target:8088',
      scan_profile: 'quick_safe',
    });

    const res = http.post(`${BASE_URL}/api/v1/assessments`, payload, { headers });
    check(res, {
      'assessment accepted or auth': (r) => r.status === 202 || r.status === 201 || r.status === 401,
    });
  });

  sleep(1);
}
