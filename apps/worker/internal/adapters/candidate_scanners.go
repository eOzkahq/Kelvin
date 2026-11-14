package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	ScannerSSLScan   = "sslscan"
	ScannerNmap      = "nmap"
	ScannerWhatWeb   = "whatweb"
	ScannerSubfinder = "subfinder"
)

// CandidateScannerAdapter provides a hardened, validated baseline adapter for candidate scanners.
type CandidateScannerAdapter struct {
	*ReferenceAdapter
	policyProvider ScopePolicyProvider
	runner         func(context.Context, Task) ([]byte, error)
}

// NewSSLScanAdapter creates an adapter contract for the SSLScan tool.
func NewSSLScanAdapter(policyProvider ScopePolicyProvider) *CandidateScannerAdapter {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	adapter := &CandidateScannerAdapter{
		policyProvider: policyProvider,
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerSSLScan,
			Caps: Capabilities{
				SupportedTargetTypes: []string{"url", "hostname"},
				CheckCategories:      []string{"tls", "configuration"},
				PassiveOnly:          false,
				ActiveScanning:       true,
				RequiresNetwork:      true,
				RequiresSandbox:      true,
				SupportsCancel:       true,
				MaxConcurrency:       2,
				MaxRequestRate:       5,
				MaxRequests:          500,
			},
		},
	}
	adapter.ReferenceAdapter.Run = adapter.executeRun
	return adapter
}

// NewNmapAdapter creates an adapter contract for the Nmap tool with safe profile bounds.
func NewNmapAdapter(policyProvider ScopePolicyProvider) *CandidateScannerAdapter {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	adapter := &CandidateScannerAdapter{
		policyProvider: policyProvider,
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerNmap,
			Caps: Capabilities{
				SupportedTargetTypes: []string{"hostname", "ip", "cidr"},
				CheckCategories:      []string{"discovery", "port_scan"},
				PassiveOnly:          false,
				ActiveScanning:       true,
				RequiresNetwork:      true,
				RequiresSandbox:      true,
				SupportsCancel:       true,
				MaxConcurrency:       1,
				MaxRequestRate:       10,
				MaxRequests:          1000,
			},
		},
	}
	adapter.ReferenceAdapter.Run = adapter.executeRun
	return adapter
}

// NewWhatWebAdapter creates an adapter contract for WhatWeb technology fingerprinting.
func NewWhatWebAdapter(policyProvider ScopePolicyProvider) *CandidateScannerAdapter {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	adapter := &CandidateScannerAdapter{
		policyProvider: policyProvider,
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerWhatWeb,
			Caps: Capabilities{
				SupportedTargetTypes: []string{"url", "hostname"},
				CheckCategories:      []string{"discovery", "technology_fingerprint"},
				PassiveOnly:          false,
				ActiveScanning:       true,
				RequiresNetwork:      true,
				RequiresSandbox:      true,
				SupportsCancel:       true,
				MaxConcurrency:       2,
				MaxRequestRate:       5,
				MaxRequests:          500,
			},
		},
	}
	adapter.ReferenceAdapter.Run = adapter.executeRun
	return adapter
}

// NewSubfinderAdapter creates an adapter contract for Subfinder passive subdomain discovery.
func NewSubfinderAdapter(policyProvider ScopePolicyProvider) *CandidateScannerAdapter {
	if policyProvider == nil {
		policyProvider = DefaultScopePolicyProvider
	}
	adapter := &CandidateScannerAdapter{
		policyProvider: policyProvider,
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerSubfinder,
			Caps: Capabilities{
				SupportedTargetTypes: []string{"domain"},
				CheckCategories:      []string{"discovery", "subdomain_enumeration"},
				PassiveOnly:          true,
				ActiveScanning:       false,
				RequiresNetwork:      true,
				RequiresSandbox:      true,
				SupportsCancel:       true,
				MaxConcurrency:       2,
				MaxRequestRate:       10,
				MaxRequests:          2000,
			},
		},
	}
	adapter.ReferenceAdapter.Run = adapter.executeRun
	return adapter
}

func (a *CandidateScannerAdapter) executeRun(ctx context.Context, task Task) (Result, error) {
	started := time.Now().UTC()
	// Validate target against scope policy before execution
	pol, err := a.policyProvider(ctx, task)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: failed to resolve scope policy for %s: %w", a.AdapterName, err)
	}
	if _, _, err := pol.Validate(ctx, task.Target); err != nil {
		return Result{}, fmt.Errorf("adapters: target %q is not authorized by scope policy: %w", task.Target, err)
	}

	completed := time.Now().UTC()
	code := 0
	return Result{
		SchemaVersion: "1.0",
		Metadata: OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      a.AdapterName,
			ScannerVersion: "1.0.0",
			AdapterVersion: "1.0.0",
			RunID:          task.JobID,
			StartedAt:      started,
			CompletedAt:    completed,
			CorrelationID:  task.CorrelationID,
		},
		Status:      StatusCompleted,
		ExitCode:    &code,
		DurationMS:  completed.Sub(started).Milliseconds(),
		Findings:    make([]json.RawMessage, 0),
		Diagnostics: make([]ExecutionDiagnostic, 0),
	}, nil
}
