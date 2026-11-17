package adapters

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNucleiAdapter_InitializationAndVerification(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	validVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion:         "3.11.1",
			AdapterVersion:         "1.0.0",
			ImageReference:         "kelvin/scanner-nuclei:3.11.1",
			ImageDigest:            "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696",
			TemplateCatalogVersion: "kelvin.safe.web.v1",
			TemplateCatalogDigest:  "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return []byte(`{"template-id":"git-config","info":{"name":"Git Config Disclosure","severity":"low"},"type":"http","host":"example.internal","matched-at":"https://example.internal/.git/config"}` + "\n"), nil
	}

	adapter := NewVerifiedNucleiAdapter(validVerifier, dummyRunner)
	if err := adapter.Initialize(ctx, logger); err != nil {
		t.Fatalf("adapter.Initialize failed: %v", err)
	}

	// Verify adapter capabilities
	caps := adapter.Capabilities()
	if !caps.ActiveScanning {
		t.Errorf("Nuclei adapter must support active scanning")
	}
	if !caps.RequiresSandbox {
		t.Errorf("Nuclei adapter must require sandbox execution")
	}
	if caps.MaxConcurrency > 2 {
		t.Errorf("Nuclei adapter max concurrency cannot exceed 2")
	}
}

func TestNucleiAdapter_RejectsInvalidTemplateCatalog(t *testing.T) {
	ctx := context.Background()

	invalidCatalogVerifier := func(ctx context.Context) (RuntimeVersionInfo, error) {
		return RuntimeVersionInfo{
			ScannerVersion:         "3.11.1",
			AdapterVersion:         "1.0.0",
			ImageReference:         "kelvin/scanner-nuclei:3.11.1",
			ImageDigest:            "sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696",
			TemplateCatalogVersion: "untrusted.catalog.v9",
			TemplateCatalogDigest:  "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2",
		}, nil
	}

	dummyRunner := func(ctx context.Context, task Task) ([]byte, error) {
		return nil, nil
	}

	adapter := NewVerifiedNucleiAdapter(invalidCatalogVerifier, dummyRunner)
	_, err := adapter.VerifyRuntimeVersion(ctx)
	if err == nil {
		t.Fatalf("expected error for untrusted template catalog, got nil")
	}
}

func TestResolveNucleiProfile(t *testing.T) {
	cases := []struct {
		profileID   string
		wantRate    int
		wantConc    int
		wantTags    string
		wantExclude string
	}{
		{
			profileID:   ProfileStandard,
			wantRate:    2,
			wantConc:    2,
			wantTags:    "cve,misconfig,exposure",
			wantExclude: "dos,fuzz,intrusive",
		},
		{
			profileID:   ProfileDeep,
			wantRate:    5,
			wantConc:    2,
			wantTags:    "cve,misconfig,exposure,vuln,takeover",
			wantExclude: "dos,fuzz",
		},
		{
			profileID:   ProfileSafeWeb,
			wantRate:    2,
			wantConc:    1,
			wantTags:    "safe,web,exposure",
			wantExclude: "dos,fuzz,intrusive,sqli,rce",
		},
	}

	for _, tc := range cases {
		t.Run(tc.profileID, func(t *testing.T) {
			controls := ResolveNucleiProfile(tc.profileID)
			if controls.RateLimit != tc.wantRate {
				t.Errorf("rate limit = %d, want %d", controls.RateLimit, tc.wantRate)
			}
			if controls.Concurrency != tc.wantConc {
				t.Errorf("concurrency = %d, want %d", controls.Concurrency, tc.wantConc)
			}
		})
	}
}

func TestBuildNucleiArgs_ProfileControls(t *testing.T) {
	taskStandard := Task{
		Target:    "https://example.com",
		ProfileID: ProfileStandard,
		Scanner:   ScannerNuclei,
	}
	argsStd := BuildNucleiArgs(taskStandard)
	joinedStd := " " + strings.Join(argsStd, " ") + " "

	if !strings.Contains(joinedStd, " -tags cve,misconfig,exposure ") {
		t.Errorf("standard profile missing expected tags in argv: %v", argsStd)
	}
	if !strings.Contains(joinedStd, " -exclude-tags dos,fuzz,intrusive ") {
		t.Errorf("standard profile missing expected exclude-tags in argv: %v", argsStd)
	}
	if !strings.Contains(joinedStd, " -rl 2 ") {
		t.Errorf("standard profile missing -rl 2 in argv: %v", argsStd)
	}

	taskDeep := Task{
		Target:    "https://example.com",
		ProfileID: ProfileDeep,
		Scanner:   ScannerNuclei,
	}
	argsDeep := BuildNucleiArgs(taskDeep)
	joinedDeep := " " + strings.Join(argsDeep, " ") + " "

	if !strings.Contains(joinedDeep, " -tags cve,misconfig,exposure,vuln,takeover ") {
		t.Errorf("deep profile missing expected tags in argv: %v", argsDeep)
	}
	if !strings.Contains(joinedDeep, " -severity info,low,medium,high,critical ") {
		t.Errorf("deep profile missing expected severities in argv: %v", argsDeep)
	}
	if !strings.Contains(joinedDeep, " -rl 5 ") {
		t.Errorf("deep profile missing -rl 5 in argv: %v", argsDeep)
	}

	taskSafeWeb := Task{
		Target:    "https://example.com",
		ProfileID: ProfileSafeWeb,
		Scanner:   ScannerNuclei,
	}
	argsSafe := BuildNucleiArgs(taskSafeWeb)
	joinedSafe := " " + strings.Join(argsSafe, " ") + " "

	if !strings.Contains(joinedSafe, " -tags safe,web,exposure ") {
		t.Errorf("safeweb profile missing expected tags in argv: %v", argsSafe)
	}
	if !strings.Contains(joinedSafe, " -c 1 ") {
		t.Errorf("safeweb profile missing -c 1 in argv: %v", argsSafe)
	}
}
