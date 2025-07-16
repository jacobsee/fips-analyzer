package main

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type CryptoAnalyzer struct {
	SourceDir      string
	EntryPoint     string
	Verbose        bool
	UnapprovedOnly bool
	InitAll        bool
	CallTree       bool
	CallTreeDepth  int
}

type AnalysisResult struct {
	SourceDirectory string          `json:"source_directory"`
	EntryPoint      string          `json:"entry_point"`
	DetectedUsages  []CryptoUsage   `json:"detected_usages"`
	Summary         AnalysisSummary `json:"summary"`
}

type CryptoUsage struct {
	Package        string     `json:"package"`
	Function       string     `json:"function"`
	CallerFunc     string     `json:"caller_function"`
	CallSite       string     `json:"call_site"`
	PackagePath    string     `json:"package_path"`
	FIPSCompliance string     `json:"fips_compliant"`
	CallTree       []CallNode `json:"call_tree"`
	// field to store the call graph node for efficient batch processing
	callerNode *callgraph.Node `json:"-"`
}

type CallNode struct {
	Function    string `json:"function"`
	Package     string `json:"package"`
	PackagePath string `json:"package_path"`
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

	ssaProg, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	ssaProg.Build()

	if a.Verbose {
		fmt.Printf("Built SSA program\n")
	}

	cg := vta.CallGraph(ssautil.AllFunctions(ssaProg), nil)

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
					CallTree:       []CallNode{},
					callerNode:     node,
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

	if a.CallTree {
		a.buildCallTreesBatch(usages)
	}

	return usages
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

func (a *CryptoAnalyzer) buildCallTreesBatch(usages []CryptoUsage) {
	// Build call tree for each usage individually
	for i := range usages {
		if usages[i].callerNode != nil {
			usages[i].CallTree = a.buildCallTree(usages[i].callerNode)
		}
	}
}

func (a *CryptoAnalyzer) buildCallTree(targetNode *callgraph.Node) []CallNode {
	path := a.findShortestPathFromRoot(targetNode)

	var callTree []CallNode
	for _, node := range path {
		if node.Func != nil && node.Func.Pkg != nil {
			funcName := node.Func.String()
			pkgPath := node.Func.Pkg.Pkg.Path()
			pkgName := node.Func.Pkg.Pkg.Name()

			callNode := CallNode{
				Function:    funcName,
				Package:     pkgName,
				PackagePath: pkgPath,
			}
			callTree = append(callTree, callNode)
		}
	}

	return callTree
}

func (a *CryptoAnalyzer) findShortestPathFromRoot(targetNode *callgraph.Node) []*callgraph.Node {
	type queueItem struct {
		node *callgraph.Node
		path []*callgraph.Node
	}

	visited := make(map[*callgraph.Node]bool)
	queue := []queueItem{{targetNode, []*callgraph.Node{targetNode}}}
	visited[targetNode] = true

	for len(queue) > 0 && len(queue[0].path) <= a.CallTreeDepth {
		current := queue[0]
		queue = queue[1:]

		if len(current.node.In) == 0 {
			return current.path
		}

		if current.node.Func != nil && current.node.Func.Pkg != nil {
			pkgName := current.node.Func.Pkg.Pkg.Name()
			funcName := current.node.Func.Name()
			if (funcName == "init" || funcName == "main") && pkgName == "main" {
				return current.path
			}
		}

		for _, edge := range current.node.In {
			if edge.Caller != nil && !visited[edge.Caller] {
				visited[edge.Caller] = true
				newPath := make([]*callgraph.Node, len(current.path)+1)
				copy(newPath[1:], current.path)
				newPath[0] = edge.Caller
				queue = append(queue, queueItem{edge.Caller, newPath})
			}
		}
	}

	return []*callgraph.Node{targetNode}
}
