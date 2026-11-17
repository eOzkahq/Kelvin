package adapters

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

const sampleNmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -Pn -p 21,23,80,443,993 -sV -oX - mail.example.com" start="1763372800" version="7.95">
  <scaninfo type="syn" protocol="tcp" numservices="5" services="21,23,80,443,993"/>
  <host starttime="1763372800" endtime="1763372810">
    <status state="up" reason="conn-refused"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="mail.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" product="Linux telnetd"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="993">
        <state state="open" reason="syn-ack"/>
        <service name="imaps" product="Dovecot"/>
        <script id="ssl-enum-ciphers" output="TLSv1.2:&#xa;  ciphers:&#xa;    TLS_RSA_WITH_AES_128_CBC_SHA - weak (CBC)"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1763372810" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>`

func TestNormalizeNmapXMLReport_ValidReport(t *testing.T) {
	task := Task{
		JobID:        uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Scanner:      ScannerNmap,
		Target:       "https://mail.example.com",
		ProfileID:    "standard",
		HardDeadline: 5 * time.Minute,
	}

	started := time.Now().Add(-10 * time.Second).UTC()
	completed := time.Now().UTC()

	res, err := NormalizeNmapXMLReport(task, []byte(sampleNmapXML), "7.95", started, completed)
	if err != nil {
		t.Fatalf("unexpected error normalizing Nmap XML: %v", err)
	}

	if res.Status != StatusCompleted {
		t.Errorf("expected status %s, got %s", StatusCompleted, res.Status)
	}
	if res.Metadata.ScannerID != ScannerNmap {
		t.Errorf("expected scanner ID %s, got %s", ScannerNmap, res.Metadata.ScannerID)
	}
	if res.Metadata.ScannerVersion != "7.95" {
		t.Errorf("expected scanner version 7.95, got %s", res.Metadata.ScannerVersion)
	}

	// 4 open ports + 1 script finding = 5 findings
	if len(res.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(res.Findings))
	}

	rawFindingsStr := ""
	for _, f := range res.Findings {
		rawFindingsStr += string(f) + "\n"
	}

	// Verify plaintext telnet high severity
	if !strings.Contains(rawFindingsStr, "plaintext-protocol-high") {
		t.Error("expected plaintext-protocol-high rule finding for telnet")
	}
	// Verify plaintext ftp medium severity
	if !strings.Contains(rawFindingsStr, "plaintext-protocol-medium") {
		t.Error("expected plaintext-protocol-medium rule finding for ftp")
	}
	// Verify CBC cipher weakness medium severity
	if !strings.Contains(rawFindingsStr, "tls-cbc-default-medium") {
		t.Error("expected tls-cbc-default-medium rule finding for ssl-enum-ciphers")
	}
	// Verify open port discovery informational severity
	if !strings.Contains(rawFindingsStr, "open-service-default-informational") {
		t.Error("expected open-service-default-informational rule finding")
	}
}

func TestNormalizeNmapXMLReport_ParserGuard(t *testing.T) {
	task := Task{
		JobID:        uuid.NewString(),
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Scanner:      ScannerNmap,
		Target:       "https://mail.example.com",
		ProfileID:    "standard",
		HardDeadline: 5 * time.Minute,
	}
	started := time.Now().UTC()
	completed := started.Add(time.Second)

	// 1. Empty payload rejected
	_, err := NormalizeNmapXMLReport(task, []byte{}, "7.95", started, completed)
	if err == nil {
		t.Fatal("expected error on empty payload")
	}

	// 2. Null bytes rejected
	nullPayload := []byte("<?xml version=\"1.0\"?>\x00<nmaprun></nmaprun>")
	_, err = NormalizeNmapXMLReport(task, nullPayload, "7.95", started, completed)
	if err == nil || !errors.Is(err, parserguard.ErrContainsNullBytes) && !strings.Contains(err.Error(), "null") {
		t.Fatalf("expected null byte rejection, got: %v", err)
	}

	// 3. Invalid UTF-8 rejected
	invalidUTF8 := []byte("<?xml version=\"1.0\"?>\xff\xfe<nmaprun></nmaprun>")
	_, err = NormalizeNmapXMLReport(task, invalidUTF8, "7.95", started, completed)
	if err == nil {
		t.Fatal("expected invalid UTF-8 rejection")
	}

	// 4. Malformed XML rejected
	malformed := []byte("not xml at all")
	_, err = NormalizeNmapXMLReport(task, malformed, "7.95", started, completed)
	if err == nil {
		t.Fatal("expected malformed XML rejection")
	}
}
