# Go x/crypto FIPS compliance analysis tool

A CLI tool (and HTML viewer) for analyzing Go projects using `callgraph` to detect the usage of cryptographic algorithms from `golang.org/x/crypto` and determining their FIPS 140-2 compliance status.

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

### With Entry Point

Analyze starting from a specific entry point:

```bash
./fips-analyzer -source /path/to/source/code -entry ./main.go
```

### Include Only Non-FIPS Compliant Algorithms

Filter to only unapproved (incl. unknown and must-evaluate) algorithms:

```bash
./fips-analyzer -source /path/to/source/code -unapproved-only
```

### JSON Output

Export results to a JSON file:

```bash
./fips-analyzer -source /path/to/source/code -output results.json
```

> [!NOTE]  
> The JSON output can be dropped onto the [report visualizer](report-visualizer.html) (just open the static html in a browser) to make things nice and pleasant and colorful.

### Verbose Output

Get detailed information about detected usages:

```bash
./fips-analyzer -source /path/to/source/code -verbose
```
