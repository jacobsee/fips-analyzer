BINARY_NAME=fips-analyzer
BIN_DIR=bin

.PHONY: all clean macos-amd64 macos-arm64 linux-amd64

all: macos-amd64 macos-arm64 linux-amd64

macos-amd64:
	GOOS=darwin GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64

macos-arm64:
	GOOS=darwin GOARCH=arm64 go build -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64

clean:
	rm -f $(BIN_DIR)/$(BINARY_NAME)-*
