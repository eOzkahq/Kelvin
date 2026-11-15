package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNucleiCI_HermeticSourceBuildPipeline(t *testing.T) {
	rootPath := filepath.Join("..", "..", "..", "..")

	// 1. Verify .github/workflows/scanner-images.yml
	wfPath := filepath.Join(rootPath, ".github", "workflows", "scanner-images.yml")
	wfBytes, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("failed to read scanner-images.yml: %v", err)
	}
	wfContent := string(wfBytes)

	for _, reqInput := range []string{"nuclei_commit", "go_builder_image", "publish", "platform"} {
		if !strings.Contains(wfContent, reqInput) {
			t.Errorf("scanner-images.yml missing input parameter: %s", reqInput)
		}
	}

	if !strings.Contains(wfContent, "scripts/scanners/verify-build.sh") {
		t.Errorf("scanner-images.yml must invoke scripts/scanners/verify-build.sh")
	}

	// 2. Verify scripts/scanners/build-images.sh passes hermetic build arguments
	buildScriptPath := filepath.Join(rootPath, "scripts", "scanners", "build-images.sh")
	bsBytes, err := os.ReadFile(buildScriptPath)
	if err != nil {
		t.Fatalf("failed to read build-images.sh: %v", err)
	}
	bsContent := string(bsBytes)

	for _, reqArg := range []string{"NUCLEI_COMMIT", "GO_BUILDER_IMAGE"} {
		if !strings.Contains(bsContent, reqArg) {
			t.Errorf("build-images.sh missing hermetic argument: %s", reqArg)
		}
	}

	// 3. Verify scripts/scanners/verify-build.sh exists and checks contracts
	vbPath := filepath.Join(rootPath, "scripts", "scanners", "verify-build.sh")
	vbBytes, err := os.ReadFile(vbPath)
	if err != nil {
		t.Fatalf("failed to read verify-build.sh: %v", err)
	}
	vbContent := string(vbBytes)

	for _, contract := range []string{"10001:10001", "Architecture", "PUBLISH"} {
		if !strings.Contains(vbContent, contract) {
			t.Errorf("verify-build.sh missing check for %q", contract)
		}
	}
}
