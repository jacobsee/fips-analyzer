# Go x/crypto usage analysis tool

A CLI tool (and HTML viewer) for analyzing Go projects using `callgraph` to detect the usage of cryptographic algorithms from `golang.org/x/crypto`.

![screenshot](screenshot.png)

## Installation

```bash
go mod tidy
go build -o fips-analyzer
```

or

```bash
make all
```

to populate `bin/`.

## Usage

### Basic Analysis

Analyze all packages in a directory:

```bash
./fips-analyzer -source /path/to/source/code
```

### Specify File Patterns

Build the syntax tree from only files matching certain patterns (comma-separated):

```bash
./fips-analyzer -source /path/to/source/code -patterns main.go,foo.go
```

### Control Init Function Analysis

By default, all discovered `init` functions are loaded into the call graph. You can disable this with:

```bash
./fips-analyzer -source /path/to/source/code -init-all=false
```

### Include Call Tree Information

To include call tree information in the output (may increase computation time):

```bash
./fips-analyzer -source /path/to/source/code -call-tree
```

You can also control the maximum call tree depth (default: 10):

```bash
./fips-analyzer -source /path/to/source/code -call-tree -call-tree-depth 5
```

### JSON Output

Export results to a JSON file:

```bash
./fips-analyzer -source /path/to/source/code -output results.json
```

> [!NOTE]  
> The JSON output can be dropped onto the [report visualizer](report-visualizer.html) (just open the static html in a browser) for interactive exploration. **You can click on any node in a call graph to filter to only call graphs which include that package.**

### Verbose Output

Get detailed information about detected usages:

```bash
./fips-analyzer -source /path/to/source/code -verbose
```
