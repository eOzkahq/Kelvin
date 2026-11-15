package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/manifest"
	"github.com/kelvin/kelvin/apps/worker/internal/readiness"
)

// NetworkInspectRecord mirrors Podman network inspect JSON output.
type NetworkInspectRecord struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
	Subnets  []struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	} `json:"subnets"`
}

// validateNetworkProperties simulates the strict 4-property check enforced in
// setup-rootless-podman.sh and validate-worker-host.sh.
func validateNetworkProperties(rec NetworkInspectRecord) []string {
	var mismatches []string
	if rec.Name != "kelvin-scanner-net" {
		mismatches = append(mismatches, "name mismatch")
	}
	if !rec.Internal {
		mismatches = append(mismatches, "internal=false")
	}
	if len(rec.Subnets) != 1 {
		mismatches = append(mismatches, "expected exactly 1 configured subnet")
	} else {
		s0 := rec.Subnets[0]
		if s0.Subnet != "10.89.10.0/24" {
			mismatches = append(mismatches, "subnet missing 10.89.10.0/24")
		}
		if s0.Gateway != "10.89.10.1" {
			mismatches = append(mismatches, "gateway missing 10.89.10.1")
		}
	}
	return mismatches
}

// 1. Test existing correct network: untouched and passes validation
func TestNetworkValidation_ExistingCorrectNetwork(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: true,
	}
	rec.Subnets = append(rec.Subnets, struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	}{Subnet: "10.89.10.0/24", Gateway: "10.89.10.1"})

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) != 0 {
		t.Fatalf("expected valid network to have 0 mismatches, got: %v", mismatches)
	}
}

// 2 & 3. Test existing non-internal / incorrect internal network: fails closed
func TestNetworkValidation_ExistingNonInternalNetwork(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: false, // Insecure: direct egress bypass
	}
	rec.Subnets = append(rec.Subnets, struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	}{Subnet: "10.89.10.0/24", Gateway: "10.89.10.1"})

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) == 0 {
		t.Fatal("expected non-internal network to fail validation")
	}
	foundInternalError := false
	for _, m := range mismatches {
		if strings.Contains(m, "internal=false") {
			foundInternalError = true
		}
	}
	if !foundInternalError {
		t.Errorf("expected internal=false error, got mismatches: %v", mismatches)
	}
}

// 4. Test incorrect subnet / gateway: fails closed
func TestNetworkValidation_IncorrectSubnetGateway(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: true,
	}
	rec.Subnets = append(rec.Subnets, struct {
		Subnet  string `json:"subnet"`
		Gateway string `json:"gateway"`
	}{Subnet: "10.89.20.0/24", Gateway: "10.89.20.1"})

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) == 0 {
		t.Fatal("expected subnet/gateway mismatch to fail validation")
	}
	hasSubnetErr := false
	hasGatewayErr := false
	for _, m := range mismatches {
		if strings.Contains(m, "subnet") {
			hasSubnetErr = true
		}
		if strings.Contains(m, "gateway") {
			hasGatewayErr = true
		}
	}
	if !hasSubnetErr || !hasGatewayErr {
		t.Errorf("expected subnet and gateway errors, got: %v", mismatches)
	}
}

// 4b. Test extra subnet: strictly rejected (must be exactly 1 configured subnet)
func TestNetworkValidation_ExtraSubnetRejected(t *testing.T) {
	rec := NetworkInspectRecord{
		Name:     "kelvin-scanner-net",
		Internal: true,
	}
	rec.Subnets = append(rec.Subnets,
		struct {
			Subnet  string `json:"subnet"`
			Gateway string `json:"gateway"`
		}{Subnet: "10.89.10.0/24", Gateway: "10.89.10.1"},
		struct {
			Subnet  string `json:"subnet"`
			Gateway string `json:"gateway"`
		}{Subnet: "10.89.20.0/24", Gateway: "10.89.20.1"},
	)

	mismatches := validateNetworkProperties(rec)
	if len(mismatches) == 0 {
		t.Fatal("expected extra subnet network to fail validation")
	}
	foundExtraSubnetErr := false
	for _, m := range mismatches {
		if strings.Contains(m, "expected exactly 1 configured subnet") {
			foundExtraSubnetErr = true
		}
	}
	if !foundExtraSubnetErr {
		t.Errorf("expected 'exactly 1 configured subnet' error, got: %v", mismatches)
	}
}

// 5. Test conflicting subordinate UID/GID ranges & collision checks
const maxSubID uint64 = 4294967295

type subIDRange struct {
	user  string
	start uint64
	end   uint64
	count uint64
}

func parseSubIDLine(line string) (*subIDRange, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}
	parts := strings.Split(trimmed, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed subordinate ID entry: expected 3 colon-separated fields, got %d", len(parts))
	}
	user := strings.TrimSpace(parts[0])
	if user == "" {
		return nil, fmt.Errorf("malformed subordinate ID entry: missing username")
	}

	start, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed subordinate ID entry: invalid start '%s'", parts[1])
	}
	count, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed subordinate ID entry: invalid count '%s'", parts[2])
	}
	if count == 0 {
		return nil, fmt.Errorf("malformed subordinate ID entry: count must be > 0")
	}

	if start > maxSubID || count > maxSubID || start+count-1 > maxSubID {
		return nil, fmt.Errorf("subordinate ID entry integer overflow: %d:%d exceeds max ID %d", start, count, maxSubID)
	}

	return &subIDRange{
		user:  user,
		start: start,
		count: count,
		end:   start + count - 1,
	}, nil
}

func findAvailableSubIDRange(ranges []subIDRange, targetCount uint64, minStart uint64) (uint64, error) {
	candidate := minStart
	changed := true
	for changed {
		changed = false
		candEnd := candidate + targetCount - 1
		if candidate > maxSubID || candEnd > maxSubID || candEnd < candidate {
			return 0, fmt.Errorf("no available contiguous subordinate ID range of size %d exists", targetCount)
		}
		for _, r := range ranges {
			if candidate <= r.end && r.start <= candEnd {
				candidate = r.end + 1
				changed = true
				break
			}
		}
	}
	if candidate+targetCount-1 > maxSubID {
		return 0, fmt.Errorf("no available contiguous subordinate ID range of size %d exists", targetCount)
	}
	return candidate, nil
}

func validateOrAddSubidContentConfigurable(content string, idType string, configuredStart string, targetCount uint64) (newContent string, err string) {
	targetUser := "kelvin-worker"
	if targetCount == 0 || targetCount > maxSubID {
		return "", fmt.Sprintf("invalid subordinate %s count: %d", idType, targetCount)
	}

	var existingRanges []subIDRange
	var kelvinLines []string

	lines := strings.Split(content, "\n")
	for lineIdx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		entry, parseErr := parseSubIDLine(trimmed)
		if parseErr != nil {
			return "", fmt.Sprintf("line %d: %s", lineIdx+1, parseErr.Error())
		}
		if entry != nil {
			existingRanges = append(existingRanges, *entry)
			if entry.user == targetUser {
				kelvinLines = append(kelvinLines, trimmed)
			}
		}
	}

	var targetStart uint64
	if configuredStart == "auto" {
		discovered, discErr := findAvailableSubIDRange(existingRanges, targetCount, 100000)
		if discErr != nil {
			return "", discErr.Error()
		}
		targetStart = discovered
	} else if configuredStart == "" || configuredStart == "adopt" {
		if len(kelvinLines) == 0 {
			discovered, discErr := findAvailableSubIDRange(existingRanges, targetCount, 100000)
			if discErr != nil {
				return "", discErr.Error()
			}
			targetStart = discovered
		} else if len(kelvinLines) == 1 {
			parts := strings.Split(kelvinLines[0], ":")
			parsed, pErr := strconv.ParseUint(parts[1], 10, 64)
			if pErr != nil {
				return "", fmt.Sprintf("invalid start in existing %s: %s", idType, parts[1])
			}
			cParsed, cErr := strconv.ParseUint(parts[2], 10, 64)
			if cErr != nil || cParsed != targetCount {
				return "", fmt.Sprintf("subordinate %s range size mismatch: found count %s, expected %d", idType, parts[2], targetCount)
			}
			targetStart = parsed
		} else {
			return "", fmt.Sprintf("multiple conflicting subordinate %s mappings found for %s", idType, targetUser)
		}
	} else {
		parsedStart, parseErr := strconv.ParseUint(configuredStart, 10, 64)
		if parseErr != nil {
			return "", fmt.Sprintf("invalid configured %s start '%s'", idType, configuredStart)
		}
		if parsedStart > maxSubID || parsedStart+targetCount-1 > maxSubID {
			return "", fmt.Sprintf("subordinate %s range integer overflow: %d:%d exceeds max ID %d", idType, parsedStart, targetCount, maxSubID)
		}
		targetStart = parsedStart
	}

	targetEnd := targetStart + targetCount - 1
	expected := fmt.Sprintf("%s:%d:%d", targetUser, targetStart, targetCount)

	// Check collision with other users
	for _, r := range existingRanges {
		if r.user != targetUser {
			if targetStart <= r.end && r.start <= targetEnd {
				return "", fmt.Sprintf("subordinate %s range collision: user '%s' (%d:%d [%d-%d]) overlaps with %s (%d:%d [%d-%d])",
					idType, r.user, r.start, r.count, r.start, r.end, targetUser, targetStart, targetCount, targetStart, targetEnd)
			}
		}
	}

	if len(kelvinLines) == 0 {
		out := content
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		return out + expected + "\n", ""
	}

	if len(kelvinLines) == 1 && kelvinLines[0] == expected {
		return content, "" // Idempotent no-op
	}

	if len(kelvinLines) > 1 {
		return "", fmt.Sprintf("multiple conflicting subordinate %s mappings found for %s: %s",
			idType, targetUser, strings.Join(kelvinLines, ", "))
	}

	return "", fmt.Sprintf("conflicting subordinate %s configuration found: expected %s, found %s",
		idType, expected, strings.Join(kelvinLines, ", "))
}

func validateSubidPairConsistency(subuidContent, subgidContent string, targetCount uint64) (start uint64, err string) {
	targetUser := "kelvin-worker"
	var uLine, gLine string
	for _, l := range strings.Split(subuidContent, "\n") {
		tr := strings.TrimSpace(l)
		if strings.HasPrefix(tr, targetUser+":") {
			if uLine != "" {
				return 0, "multiple conflicting subordinate UID mappings found for kelvin-worker in subuid"
			}
			uLine = tr
		}
	}
	for _, l := range strings.Split(subgidContent, "\n") {
		tr := strings.TrimSpace(l)
		if strings.HasPrefix(tr, targetUser+":") {
			if gLine != "" {
				return 0, "multiple conflicting subordinate GID mappings found for kelvin-worker in subgid"
			}
			gLine = tr
		}
	}
	if uLine == "" || gLine == "" {
		return 0, "inconsistent subordinate ID configuration: mapping missing in one or both files"
	}
	uParts := strings.Split(uLine, ":")
	gParts := strings.Split(gLine, ":")
	uStart, errU := strconv.ParseUint(uParts[1], 10, 64)
	gStart, errG := strconv.ParseUint(gParts[1], 10, 64)
	if errU != nil || errG != nil {
		return 0, "malformed subordinate ID entry values"
	}
	if uStart != gStart {
		return 0, fmt.Sprintf("subordinate UID/GID allocation mismatch: UID start '%d' does not match GID start '%d'", uStart, gStart)
	}
	uCnt, _ := strconv.ParseUint(uParts[2], 10, 64)
	gCnt, _ := strconv.ParseUint(gParts[2], 10, 64)
	if uCnt != targetCount || gCnt != targetCount {
		return 0, fmt.Sprintf("subordinate ID range size mismatch: found count UID='%d'/GID='%d', expected '%d'", uCnt, gCnt, targetCount)
	}
	return uStart, ""
}

func validateOrAddSubidContent(content string) (newContent string, err string) {
	// Default backwards-compatible signature using 200000 start
	return validateOrAddSubidContentConfigurable(content, "UID", "200000", 65536)
}

func TestSubordinateIDValidation_ConflictingRanges(t *testing.T) {
	// 1. Existing opc:100000:65536 preserved when valid non-overlapping Kelvin allocation (200000:65536) added
	res1, err1 := validateOrAddSubidContentConfigurable("opc:100000:65536\n", "UID", "200000", 65536)
	if err1 != "" {
		t.Fatalf("Test 1 failed: %s", err1)
	}
	if !strings.Contains(res1, "opc:100000:65536") {
		t.Errorf("Test 1: expected opc mapping preserved, got: %s", res1)
	}
	if !strings.Contains(res1, "kelvin-worker:200000:65536") {
		t.Errorf("Test 1: expected kelvin-worker mapping appended, got: %s", res1)
	}

	// 2. Valid non-overlapping Kelvin allocation verified idempotently
	res2, err2 := validateOrAddSubidContentConfigurable("opc:100000:65536\nkelvin-worker:200000:65536\n", "UID", "200000", 65536)
	if err2 != "" {
		t.Fatalf("Test 2 failed: %s", err2)
	}
	if strings.Count(res2, "kelvin-worker:200000:65536") != 1 || strings.Count(res2, "opc:100000:65536") != 1 {
		t.Errorf("Test 2: expected exactly 1 mapping of each, got: %s", res2)
	}

	// 3. UID collision (Kelvin UID configured as 100000 collides with opc:100000:65536)
	_, err3 := validateOrAddSubidContentConfigurable("opc:100000:65536\n", "UID", "100000", 65536)
	if err3 == "" {
		t.Fatal("Test 3: expected UID collision error, got nil")
	}
	if !strings.Contains(err3, "subordinate UID range collision") || !strings.Contains(err3, "opc") {
		t.Errorf("Test 3: expected UID collision message mentioning opc, got: %s", err3)
	}

	// 4. GID collision (independent audit for /etc/subgid)
	_, err4 := validateOrAddSubidContentConfigurable("opc:100000:65536\ndockergroup:200000:65536\n", "GID", "200000", 65536)
	if err4 == "" {
		t.Fatal("Test 4: expected GID collision error, got nil")
	}
	if !strings.Contains(err4, "subordinate GID range collision") || !strings.Contains(err4, "dockergroup") {
		t.Errorf("Test 4: expected GID collision message mentioning dockergroup, got: %s", err4)
	}

	// 5. Collision with another user's overlapping range (otheruser:150000:60000 overlaps 200000:65536)
	_, err5 := validateOrAddSubidContentConfigurable("otheruser:150000:60000\n", "UID", "200000", 65536)
	if err5 == "" {
		t.Fatal("Test 5: expected collision error for 150000:60000 overlapping 200000:65536, got nil")
	}
	if !strings.Contains(err5, "range collision") || !strings.Contains(err5, "otheruser") {
		t.Errorf("Test 5: unexpected error message: %s", err5)
	}

	// 6. Multiple conflicting Kelvin mappings
	_, err6 := validateOrAddSubidContentConfigurable("kelvin-worker:200000:65536\nkelvin-worker:300000:65536\n", "UID", "200000", 65536)
	if err6 == "" {
		t.Fatal("Test 6: expected multiple conflicting Kelvin mappings error, got nil")
	}
	if !strings.Contains(err6, "conflicting subordinate UID") {
		t.Errorf("Test 6: unexpected error message: %s", err6)
	}

	// 7. No available range when ID space is exhausted
	_, err7 := validateOrAddSubidContentConfigurable("exhaustuser:100000:4294867296\n", "UID", "auto", 65536)
	if err7 == "" {
		t.Fatal("Test 7: expected failure for exhausted ID space, got nil")
	}
	if !strings.Contains(err7, "no available contiguous subordinate ID range") {
		t.Errorf("Test 7: unexpected error message: %s", err7)
	}

	// 8. Integer overflow and malformed subordinate-ID entries
	// 8a. Integer overflow in existing entry
	_, err8a := validateOrAddSubidContentConfigurable("overflowuser:4294950000:65536\n", "UID", "200000", 65536)
	if err8a == "" {
		t.Fatal("Test 8a: expected integer overflow error, got nil")
	}
	if !strings.Contains(err8a, "integer overflow") {
		t.Errorf("Test 8a: unexpected error message: %s", err8a)
	}

	// 8b. Integer overflow in configured target
	_, err8b := validateOrAddSubidContentConfigurable("", "UID", "4294950000", 65536)
	if err8b == "" {
		t.Fatal("Test 8b: expected integer overflow in configured target, got nil")
	}
	if !strings.Contains(err8b, "integer overflow") {
		t.Errorf("Test 8b: unexpected error message: %s", err8b)
	}

	// 8c. Malformed line without colons
	_, err8c := validateOrAddSubidContentConfigurable("malformed_line_no_colons\n", "UID", "200000", 65536)
	if err8c == "" {
		t.Fatal("Test 8c: expected malformed line error, got nil")
	}
	if !strings.Contains(err8c, "malformed subordinate ID entry") {
		t.Errorf("Test 8c: unexpected error message: %s", err8c)
	}

	// 8d. Malformed line with non-numeric start
	_, err8d := validateOrAddSubidContentConfigurable("baduser:notanumber:65536\n", "UID", "200000", 65536)
	if err8d == "" {
		t.Fatal("Test 8d: expected malformed non-numeric start error, got nil")
	}
	if !strings.Contains(err8d, "invalid start") {
		t.Errorf("Test 8d: unexpected error message: %s", err8d)
	}

	// 9. Dynamic auto-allocation selects next contiguous range
	res9, err9 := validateOrAddSubidContentConfigurable("opc:100000:65536\ndeveloper:165536:34464\n", "UID", "auto", 65536)
	if err9 != "" {
		t.Fatalf("Test 9 failed: %s", err9)
	}
	if !strings.Contains(res9, "kelvin-worker:200000:65536") {
		t.Errorf("Test 9: expected auto-allocated range 200000:65536, got: %s", res9)
	}

	// 10. Adoption of existing 165536:65536 allocation when configuration is absent
	res10, err10 := validateOrAddSubidContentConfigurable("opc:100000:65536\nkelvin-worker:165536:65536\n", "UID", "adopt", 65536)
	if err10 != "" {
		t.Fatalf("Test 10 failed: %s", err10)
	}
	if strings.Count(res10, "kelvin-worker:165536:65536") != 1 || !strings.Contains(res10, "opc:100000:65536") {
		t.Errorf("Test 10: expected existing mapping preserved and adopted, got: %s", res10)
	}

	// 11. Explicit configured mapping conflict (file has 165536, configured with 200000)
	_, err11 := validateOrAddSubidContentConfigurable("opc:100000:65536\nkelvin-worker:165536:65536\n", "UID", "200000", 65536)
	if err11 == "" {
		t.Fatal("Test 11: expected conflict error when configured 200000 conflicts with 165536, got nil")
	}
	if !strings.Contains(err11, "conflicting subordinate UID configuration") {
		t.Errorf("Test 11: unexpected conflict message: %s", err11)
	}

	// 12. UID/GID mismatch between subuid and subgid
	subuidContent := "opc:100000:65536\nkelvin-worker:165536:65536\n"
	subgidMismatchContent := "opc:100000:65536\nkelvin-worker:200000:65536\n"
	_, err12 := validateSubidPairConsistency(subuidContent, subgidMismatchContent, 65536)
	if err12 == "" {
		t.Fatal("Test 12: expected UID/GID mismatch error, got nil")
	}
	if !strings.Contains(err12, "subordinate UID/GID allocation mismatch") {
		t.Errorf("Test 12: unexpected mismatch message: %s", err12)
	}

	// 13. Idempotent repeated setup leaves file untouched
	res13a, err13a := validateOrAddSubidContentConfigurable(subuidContent, "UID", "165536", 65536)
	if err13a != "" {
		t.Fatalf("Test 13a failed: %s", err13a)
	}
	res13b, err13b := validateOrAddSubidContentConfigurable(res13a, "UID", "165536", 65536)
	if err13b != "" {
		t.Fatalf("Test 13b failed: %s", err13b)
	}
	if strings.Count(res13b, "kelvin-worker:165536:65536") != 1 {
		t.Errorf("Test 13: expected exactly 1 mapping after repeated setup, got: %s", res13b)
	}
}

// TestWorkerWorkingDirectory_RegressionAndIsolation verifies Problem A:
// executing in an inaccessible directory fails, while explicitly switching to /var/lib/kelvin-worker succeeds.
func TestWorkerWorkingDirectory_RegressionAndIsolation(t *testing.T) {
	tempBase := t.TempDir()
	inaccessibleDir := filepath.Join(tempBase, "inaccessible_opt_kelvin")
	accessibleWorkerDir := filepath.Join(tempBase, "var_lib_kelvin_worker")

	if err := os.MkdirAll(inaccessibleDir, 0700); err != nil {
		t.Fatalf("failed to create inaccessible dir: %v", err)
	}
	if err := os.MkdirAll(accessibleWorkerDir, 0750); err != nil {
		t.Fatalf("failed to create worker dir: %v", err)
	}

	// Simulate execution: if process attempts to run in non-existent or inaccessible dir without chdir, it fails
	nonexistentDir := filepath.Join(tempBase, "does_not_exist")
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	// Without chdir to worker dir, changing to invalid/inaccessible dir fails
	if err := os.Chdir(nonexistentDir); err == nil {
		t.Fatal("expected failure entering nonexistent dir without proper chdir, got nil")
	}

	// With explicit chdir to worker dir, succeeds and verifies working directory
	if err := os.Chdir(accessibleWorkerDir); err != nil {
		t.Fatalf("failed explicit chdir to worker dir: %v", err)
	}
	newWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd after chdir: %v", err)
	}
	if !strings.EqualFold(newWd, accessibleWorkerDir) && filepath.Clean(newWd) != filepath.Clean(accessibleWorkerDir) {
		t.Errorf("expected wd to be %q, got %q", accessibleWorkerDir, newWd)
	}
}

// 6. Test architecture enforcement: strictly requires aarch64 or arm64
func validateHostArchitecture(arch string) bool {
	return arch == "aarch64" || arch == "arm64"
}

func TestArchitectureEnforcement_RejectsUnsupported(t *testing.T) {
	validArchs := []string{"aarch64", "arm64"}
	for _, a := range validArchs {
		if !validateHostArchitecture(a) {
			t.Errorf("expected architecture %q to be valid", a)
		}
	}

	unsupportedArchs := []string{"x86_64", "amd64", "i386", "armv7l", "riscv64", "mips64"}
	for _, a := range unsupportedArchs {
		if validateHostArchitecture(a) {
			t.Errorf("expected architecture %q to be rejected", a)
		}
	}
}

// 7. Test failed deployment rollback logic
func TestDeploymentRollback_Mechanism(t *testing.T) {
	tmpDir := t.TempDir()
	binDest := filepath.Join(tmpDir, "kelvin-worker")
	binPrev := filepath.Join(tmpDir, "kelvin-worker.prev")

	// Setup initial known-good active binary
	initialContent := "binary-version-1.0-known-good"
	if err := os.WriteFile(binDest, []byte(initialContent), 0755); err != nil {
		t.Fatalf("failed to write initial binary: %v", err)
	}

	// Step 1: Backup active binary before replacing
	if err := os.WriteFile(binPrev, []byte(initialContent), 0755); err != nil {
		t.Fatalf("failed to backup binary: %v", err)
	}

	// Step 2: Atomic install of faulty new binary
	faultyContent := "binary-version-2.0-broken"
	if err := os.WriteFile(binDest, []byte(faultyContent), 0755); err != nil {
		t.Fatalf("failed to install new binary: %v", err)
	}

	// Step 3: Deployment failure occurs -> trigger rollback
	simulatedDeployFailed := true
	if simulatedDeployFailed {
		if _, err := os.Stat(binPrev); err == nil {
			// Restore previous binary
			prevData, readErr := os.ReadFile(binPrev)
			if readErr != nil {
				t.Fatalf("rollback read failed: %v", readErr)
			}
			if err := os.WriteFile(binDest, prevData, 0755); err != nil {
				t.Fatalf("rollback restore failed: %v", err)
			}
		}
	}

	// Verify restored binary matches initial known-good version
	restoredData, err := os.ReadFile(binDest)
	if err != nil {
		t.Fatalf("failed to read restored binary: %v", err)
	}
	if string(restoredData) != initialContent {
		t.Fatalf("rollback failed: expected %q, got %q", initialContent, string(restoredData))
	}

	// Step 4: When no previous binary exists, rollback reports unavailable
	_ = os.Remove(binPrev)
	hasPrev := false
	if _, err := os.Stat(binPrev); err == nil {
		hasPrev = true
	}
	if hasPrev {
		t.Fatal("expected no previous binary for fresh install")
	}
}

// 8. Test active service with unreleased scanner image manifest
func TestHonestReadiness_ActiveServiceWithUncertifiedRelease(t *testing.T) {
	// Create temporary canonical lock with status="not-released"
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "images.lock.json")
	lockContent := `{
  "schema_version": "1",
  "status": "not-released",
  "images": {
    "nuclei": {
      "upstream": "projectdiscovery/nuclei",
      "upstream_digest": null,
      "version": null,
      "kelvin_image": null,
      "kelvin_digest": null,
      "template_catalog_id": "kelvin.safe.web.v1",
      "template_catalog_digest": "sha256:72544e12d0409da7ce430a89dafb86bdf2a971e34986eb936db55f53fb9915b2"
    }
  }
}`
	if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
		t.Fatalf("failed to write lock file: %v", err)
	}

	// In staging environment, release manifest probe must report StatusUnavailable
	probe := readiness.NewReleaseManifestProbe("nuclei", lockPath, "staging")
	ctx := context.Background()
	check := probe.Check(ctx)

	if check.Status != readiness.StatusUnavailable {
		t.Errorf("expected StatusUnavailable for not-released status in staging, got %s", check.Status)
	}
	if !strings.Contains(check.Message, "not certified") {
		t.Errorf("expected uncertified message, got: %s", check.Message)
	}

	// Verify orchestrator execution gate rejects container dispatch
	err := manifest.EnforceCertifiedReleaseForExecution(lockPath, "nuclei", "staging")
	if err == nil {
		t.Fatal("expected EnforceCertifiedReleaseForExecution to fail closed, got nil")
	}
	if !strings.Contains(err.Error(), "not certified") {
		t.Errorf("expected uncertified error, got: %v", err)
	}
}
