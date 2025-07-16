package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var (
		sourceDir      = flag.String("source", "", "Source code directory to analyze")
		entryPoint     = flag.String("entry", "", "Entry point (main package or specific package)")
		outputFile     = flag.String("output", "", "Output file for results (JSON format)")
		verbose        = flag.Bool("verbose", false, "Enable verbose output (default: false)")
		unapprovedOnly = flag.Bool("unapproved-only", false, "Show only unapproved usages (default: false)")
		initAll        = flag.Bool("init-all", true, "Include all discovered init functions in the analysis (default: true)")
		callTree       = flag.Bool("call-tree", false, "Include call tree in output (increases computation time, default: false)")
		callTreeDepth  = flag.Int("call-tree-depth", 10, "Maximum depth for call tree analysis (default: 10, lower values improve performance)")
	)
	flag.Parse()

	if *sourceDir == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -source <directory> [-entry <package>] [-output <file>] [-verbose] [-unapproved-only] [-denoise] [-call-tree] [-call-tree-depth <int>]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	analyzer := &CryptoAnalyzer{
		SourceDir:      *sourceDir,
		EntryPoint:     *entryPoint,
		Verbose:        *verbose,
		UnapprovedOnly: *unapprovedOnly,
		InitAll:        *initAll,
		CallTree:       *callTree,
		CallTreeDepth:  *callTreeDepth,
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

	if !result.Summary.FIPSCompliant {
		os.Exit(1)
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
	if result.EntryPoint != "" {
		fmt.Printf("Entry Point: %s\n", result.EntryPoint)
	}
	fmt.Printf("\n")

	fmt.Printf("=== Summary ===\n")
	fmt.Printf("Total Usages: %d\n", result.Summary.TotalUsages)
	fmt.Printf("FIPS Approved: %d\n", result.Summary.ApprovedUsages)
	fmt.Printf("Rejected: %d\n", result.Summary.RejectedUsages)
	fmt.Printf("Must Evaluate Manually: %d\n", result.Summary.MustEvaluateUsages)
	fmt.Printf("Unknown x/crypto Packages: %d\n", result.Summary.UnknownUsages)
	fmt.Printf("FIPS Compliant: %t\n", result.Summary.FIPSCompliant)
	fmt.Printf("\n")

	if verbose {
		if len(result.DetectedUsages) > 0 {
			fmt.Printf("=== Detected Crypto Algorithm Usages ===\n")

			// Group by FIPS status
			approved := []CryptoUsage{}
			rejected := []CryptoUsage{}
			mustEvaluate := []CryptoUsage{}
			unknown := []CryptoUsage{}

			for _, usage := range result.DetectedUsages {
				switch usage.FIPSCompliance {
				case "approved":
					approved = append(approved, usage)
				case "rejected":
					rejected = append(rejected, usage)
				case "must_evaluate_manually":
					mustEvaluate = append(mustEvaluate, usage)
				case "unknown":
					unknown = append(unknown, usage)
				}
			}

			if len(approved) > 0 {
				fmt.Printf("\n✅ FIPS Approved Algorithms:\n")
				for _, usage := range approved {
					printUsage(usage)
				}
			}

			if len(rejected) > 0 {
				fmt.Printf("\n❌ Rejected Algorithms:\n")
				for _, usage := range rejected {
					printUsage(usage)
				}
			}

			if len(mustEvaluate) > 0 {
				fmt.Printf("\n🔍 Must Evaluate Manually:\n")
				for _, usage := range mustEvaluate {
					printUsage(usage)
				}
			}

			if len(unknown) > 0 {
				fmt.Printf("\n❓ Unknown x/crypto Packages:\n")
				for _, usage := range unknown {
					printUsage(usage)
				}
			}
		} else {
			fmt.Printf("No cryptographic algorithm usages detected.\n")
		}
	}

	fmt.Printf("\n")
	if !result.Summary.FIPSCompliant {
		if result.Summary.RejectedUsages > 0 {
			fmt.Printf("⚠️  WARNING: Rejected algorithms detected!\n")
		}
		if result.Summary.MustEvaluateUsages > 0 {
			fmt.Printf("⚠️  WARNING: Algorithms requiring manual evaluation detected!\n")
		}
		if result.Summary.UnknownUsages > 0 {
			fmt.Printf("⚠️  WARNING: Unknown x/crypto packages detected!\n")
		}
	} else {
		fmt.Printf("✅ All detected algorithms are FIPS compliant.\n")
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
}
