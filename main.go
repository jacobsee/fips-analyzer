package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	var (
		sourceDir     = flag.String("source", "", "Source code directory to analyze")
		patterns      = flag.String("patterns", "", "Build the call graph from files matching these patterns (comma-separated, e.g., 'main.go,stuff.go')")
		outputFile    = flag.String("output", "", "Output file for results (JSON format)")
		verbose       = flag.Bool("verbose", false, "Enable verbose output (default: false)")
		initAll       = flag.Bool("init-all", true, "Include all discovered init functions in the analysis (default: true)")
		callTree      = flag.Bool("call-tree", false, "Include call tree in output (increases computation time, default: false)")
		callTreeDepth = flag.Int("call-tree-depth", 10, "Maximum depth for call tree analysis (default: 10, lower values improve performance)")
	)
	flag.Parse()

	if *sourceDir == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -source <directory> [-entry <package>] [-output <file>] [-verbose] [-unapproved-only] [-denoise] [-call-tree] [-call-tree-depth <int>]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	patternsList := []string{}
	if *patterns != "" {
		patternsList = append(patternsList, strings.Split(*patterns, ",")...)
	} else {
		patternsList = append(patternsList, "./...")
	}

	analyzer := &CryptoAnalyzer{
		SourceDir:     *sourceDir,
		Patterns:      patternsList,
		Verbose:       *verbose,
		InitAll:       *initAll,
		CallTree:      *callTree,
		CallTreeDepth: *callTreeDepth,
	}

	result, err := analyzer.Analyze()
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	if *outputFile != "" {
		if err := writeResultsToFile(result, *outputFile); err != nil {
			log.Fatalf("Failed to write results to file: %v", err)
		}
		fmt.Printf("Results written to %s\n", *outputFile)
	} else {
		printResults(result, *verbose)
	}
}

func writeResultsToFile(result *AnalysisResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func printResults(result *AnalysisResult, verbose bool) {
	fmt.Printf("Source Directory: %s\n", result.SourceDirectory)
	fmt.Printf("Patterns: %s\n", strings.Join(result.Patterns, ", "))
	fmt.Printf("\n")

	fmt.Printf("=== Summary ===\n")
	fmt.Printf("Total Usages: %d\n", result.Summary.TotalUsages)
	fmt.Printf("\n")

	if verbose {
		if len(result.DetectedUsages) > 0 {
			fmt.Printf("=== Detected Usages ===\n")

			for _, usage := range result.DetectedUsages {
				printUsage(usage)
			}
		} else {
			fmt.Printf("No x/crypto module usages detected.\n")
		}
	}
}

func printUsage(usage CryptoUsage) {
	fmt.Printf(" >> Package: %s\n", usage.Package)
	fmt.Printf("    Function: %s\n", usage.Function)
	fmt.Printf("    Called by: %s\n", usage.CallerFunc)
	fmt.Printf("    Package Path: %s\n", usage.PackagePath)
	if usage.CallSite != "" {
		fmt.Printf("    Call Site: %s\n", usage.CallSite)
	}
	if len(usage.CallTree) > 0 {
		fmt.Printf("    Call Tree:\n")
		for _, node := range usage.CallTree {
			fmt.Printf("      - %s (%s)\n", node.Function, node.Package)
		}
	} else {
		fmt.Printf("    Call Tree: Not available\n")
	}
}
