BINARY_NAME=pipeguard
VERSION=0.1.0
BUILD_DIR=./cmd/pipeguard
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"

.PHONY: build clean test scan-examples lint release

## Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) $(BUILD_DIR)/

## Build for all platforms
build-all:
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64   $(BUILD_DIR)/
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64   $(BUILD_DIR)/
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64  $(BUILD_DIR)/
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64  $(BUILD_DIR)/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe $(BUILD_DIR)/

## Run tests
test:
	go test -v -race ./...

## Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Run linter
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run ./...

## Format code
fmt:
	gofmt -s -w .
	goimports -w .

## Scan example files
scan-examples: build
	./$(BINARY_NAME) scan examples/

## Scan with fix suggestions
scan-fix: build
	./$(BINARY_NAME) scan examples/ --fix

## Scan with JSON output
scan-json: build
	./$(BINARY_NAME) scan examples/ --format json | jq .

## Scan with SARIF output
scan-sarif: build
	./$(BINARY_NAME) scan examples/ --format sarif --output report.sarif
	@echo "SARIF report: report.sarif"

## Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f coverage.out coverage.html
	rm -f report.sarif report.json

## Show version
version:
	@echo $(VERSION)

## Install to GOPATH/bin
install: build
	cp $(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)

## Show help
help:
	@echo "PipeGuard v$(VERSION) — Pipeline Security & Quality Scanner"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the binary"
	@echo "  build-all      Build for all platforms"
	@echo "  test           Run tests"
	@echo "  coverage       Run tests with coverage report"
	@echo "  lint           Run golangci-lint"
	@echo "  fmt            Format code"
	@echo "  scan-examples  Scan example files"
	@echo "  scan-fix       Scan with fix suggestions"
	@echo "  scan-json      Scan with JSON output"
	@echo "  scan-sarif     Scan with SARIF output"
	@echo "  clean          Remove build artifacts"
	@echo "  install        Install to GOPATH/bin"
	@echo "  help           Show this help"
