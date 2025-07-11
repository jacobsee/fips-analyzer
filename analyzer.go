package main

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"
)

type CryptoAnalyzer struct {
	SourceDir      string
	EntryPoint     string
	Verbose        bool
	UnapprovedOnly bool
	Denoise        bool
}

type AnalysisResult struct {
	SourceDirectory string          `json:"source_directory"`
	EntryPoint      string          `json:"entry_point"`
	DetectedUsages  []CryptoUsage   `json:"detected_usages"`
	Summary         AnalysisSummary `json:"summary"`
}

type CryptoUsage struct {
	Package        string `json:"package"`
	Function       string `json:"function"`
	CallerFunc     string `json:"caller_function"`
	CallSite       string `json:"call_site"`
	PackagePath    string `json:"package_path"`
	FIPSCompliance string `json:"fips_compliant"`
}

type AnalysisSummary struct {
	TotalUsages        int  `json:"total_usages"`
	ApprovedUsages     int  `json:"approved_usages"`
	RejectedUsages     int  `json:"rejected_usages"`
	MustEvaluateUsages int  `json:"must_evaluate_usages"`
	UnknownUsages      int  `json:"unknown_usages"`
	FIPSCompliant      bool `json:"fips_compliant"`
}

func (a *CryptoAnalyzer) Analyze() (*AnalysisResult, error) {
	if a.Verbose {
		fmt.Printf("Analyzing source directory: %s\n", a.SourceDir)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps,
		Dir: a.SourceDir,
	}

	var patterns []string
	if a.EntryPoint != "" {
		patterns = []string{a.EntryPoint}
	} else {
		// Load all packages in the source directory
		patterns = []string{"./..."}
	}

	if a.Verbose {
		fmt.Printf("Loading packages with patterns: %v\n", patterns)
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %v", err)
	}

	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("packages contain errors")
	}

	if a.Verbose {
		fmt.Printf("Loaded %d packages\n", len(pkgs))
	}

	ssaProg, _ := ssautil.AllPackages(pkgs, 0)
	ssaProg.Build()

	if a.Verbose {
		fmt.Printf("Built SSA program\n")
	}

	cg := cha.CallGraph(ssaProg)

	if a.Verbose {
		fmt.Printf("Built call graph with %d nodes\n", len(cg.Nodes))
	}

	usages := a.findCryptoUsages(cg)

	if a.UnapprovedOnly {
		filtered := []CryptoUsage{}
		for _, usage := range usages {
			if usage.FIPSCompliance != "approved" {
				filtered = append(filtered, usage)
			}
		}
		usages = filtered
	}

	if a.Denoise {
		filtered := []CryptoUsage{}
		for _, usage := range usages {
			if !isFilteredPackage(usage.PackagePath) {
				filtered = append(filtered, usage)
			}
		}
		usages = filtered
	}

	result := &AnalysisResult{
		SourceDirectory: a.SourceDir,
		EntryPoint:      a.EntryPoint,
		DetectedUsages:  usages,
		Summary:         calculateSummary(usages),
	}

	return result, nil
}

func (a *CryptoAnalyzer) findCryptoUsages(cg *callgraph.Graph) []CryptoUsage {
	var usages []CryptoUsage

	for _, node := range cg.Nodes {
		if node.Func == nil {
			continue
		}

		funcName := node.Func.String()
		pkg := node.Func.Pkg

		if pkg == nil {
			continue
		}

		packagePath := pkg.Pkg.Path()

		// Check each function call
		for _, edge := range node.Out {
			if edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			calledFunc := edge.Callee.Func
			calledPkg := calledFunc.Pkg

			if calledPkg == nil {
				continue
			}

			calledPkgPath := calledPkg.Pkg.Path()

			var fipsStatus string
			var shouldInclude bool

			// Check if this is a call to a known crypto package
			if pkgStatus, found := knownPackages[calledPkgPath]; found {
				fipsStatus = pkgStatus.FIPSStatus
				shouldInclude = true
			} else if strings.HasPrefix(calledPkgPath, "golang.org/x/crypto/") {
				// Unknown x/crypto package
				fipsStatus = "unknown"
				shouldInclude = true
			}

			if shouldInclude {
				funcNameParts := strings.Split(calledFunc.String(), ".")
				functionName := funcNameParts[len(funcNameParts)-1]

				usage := CryptoUsage{
					Package:        calledPkgPath,
					Function:       functionName,
					CallerFunc:     funcName,
					CallSite:       edge.Description(),
					PackagePath:    packagePath,
					FIPSCompliance: fipsStatus,
				}
				usages = append(usages, usage)

				if a.Verbose {
					fmt.Printf("Found crypto usage: %s.%s in %s (status: %s)\n", calledPkgPath, functionName, funcName, fipsStatus)
				}
			}
		}
	}

	sort.Slice(usages, func(i, j int) bool {
		if usages[i].Package == usages[j].Package {
			return usages[i].CallerFunc < usages[j].CallerFunc
		}
		return usages[i].Package < usages[j].Package
	})

	return usages
}

func isFilteredPackage(pkgPath string) bool {
	return strings.HasPrefix(pkgPath, "runtime") ||
		strings.HasPrefix(pkgPath, "internal/") ||
		strings.HasPrefix(pkgPath, "crypto") ||
		strings.HasPrefix(pkgPath, "encoding/") ||
		strings.HasPrefix(pkgPath, "fmt") ||
		strings.HasPrefix(pkgPath, "io") ||
		strings.HasPrefix(pkgPath, "log") ||
		strings.HasPrefix(pkgPath, "strings") ||
		strings.HasPrefix(pkgPath, "bytes") ||
		strings.HasPrefix(pkgPath, "sync") ||
		strings.HasPrefix(pkgPath, "time") ||
		strings.HasPrefix(pkgPath, "golang.org/x/crypto")
}

func calculateSummary(usages []CryptoUsage) AnalysisSummary {
	summary := AnalysisSummary{
		TotalUsages: len(usages),
	}

	for _, usage := range usages {
		switch usage.FIPSCompliance {
		case "approved":
			summary.ApprovedUsages++
		case "rejected":
			summary.RejectedUsages++
		case "must_evaluate_manually":
			summary.MustEvaluateUsages++
		case "unknown":
			summary.UnknownUsages++
		}
	}

	summary.FIPSCompliant = summary.RejectedUsages == 0 && summary.MustEvaluateUsages == 0 && summary.UnknownUsages == 0

	return summary
}
