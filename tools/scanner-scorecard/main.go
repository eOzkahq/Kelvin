package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		inputPath  string
		outputJSON string
		outputMD   string
	)

	flag.StringVar(&inputPath, "input", "", "Path to ScorecardInput JSON file (required)")
	flag.StringVar(&outputJSON, "output-json", "", "Optional path to write scorecard.json")
	flag.StringVar(&outputMD, "output-md", "", "Optional path to write SCORECARD.md")
	flag.Parse()

	if inputPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --input <path> is required")
		flag.Usage()
		os.Exit(2)
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to read input file: %v\n", err)
		os.Exit(2)
	}

	var input ScorecardInput
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to parse input JSON: %v\n", err)
		os.Exit(2)
	}

	sc := Evaluate(input)

	// Print summary to terminal
	fmt.Print(sc.ToMarkdown())

	if outputJSON != "" {
		jsonData, err := sc.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal scorecard JSON: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(outputJSON, jsonData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to write JSON output: %v\n", err)
			os.Exit(2)
		}
	}

	if outputMD != "" {
		if err := os.WriteFile(outputMD, []byte(sc.ToMarkdown()), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to write Markdown output: %v\n", err)
			os.Exit(2)
		}
	}

	if sc.ReleaseEligibility == "ELIGIBLE" {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
