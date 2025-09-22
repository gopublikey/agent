.PHONY: build clean test fmt vet lint install version help

# Binary name
BINARY_NAME=pkagent

# Version (extracted from main.go)
VERSION := $(shell grep -E '^\s*Version\s*=' main.go | sed 's/.*Version.*=.*"\([^"]*\)".*/\1/')

# Build flags
BUILD_FLAGS=-ldflags "-X main.Version=$(VERSION)"

# Default target
all: fmt vet test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	go build $(BUILD_FLAGS) -o $(BINARY_NAME) .

# Build for multiple platforms (Linux only)
build-all: dist
	@echo "Building for all Linux architectures..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-linux-x86_64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-linux-aarch64 .
	GOOS=linux GOARCH=arm CGO_ENABLED=0 go build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-linux-arm .
	GOOS=linux GOARCH=386 CGO_ENABLED=0 go build $(BUILD_FLAGS) -o dist/$(BINARY_NAME)-linux-i386 .

# Create distribution directory
dist:
	mkdir -p dist

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -rf dist/

# Format Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# Vet Go code
vet:
	@echo "Vetting Go code..."
	go vet ./...

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run the agent in dry-run mode for testing
dry-run:
	@echo "Running agent in dry-run mode..."
	@if [ -z "$(TOKEN)" ] || [ -z "$(ENDPOINT)" ]; then \
		echo "Error: Please set TOKEN and ENDPOINT environment variables"; \
		echo "Example: make dry-run TOKEN=pk_yourtoken ENDPOINT=https://your.domain.com"; \
		exit 1; \
	fi
	./$(BINARY_NAME) --token=$(TOKEN) --endpoint=$(ENDPOINT) --dry-run

# Install the agent locally (requires sudo for system mode)
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY_NAME)"

# Install for current user only
install-user: build
	@echo "Installing $(BINARY_NAME) for current user..."
	mkdir -p $(HOME)/.local/bin
	cp $(BINARY_NAME) $(HOME)/.local/bin/
	@echo "Installed to $(HOME)/.local/bin/$(BINARY_NAME)"

# Install as systemd service (requires TOKEN and ENDPOINT)
install-service: build
	@if [ -z "$(TOKEN)" ] || [ -z "$(ENDPOINT)" ]; then \
		echo "Error: Please set TOKEN and ENDPOINT environment variables"; \
		echo "Example: make install-service TOKEN=pk_yourtoken ENDPOINT=https://your.domain.com"; \
		exit 1; \
	fi
	sudo ./$(BINARY_NAME) install --token=$(TOKEN) --endpoint=$(ENDPOINT)

# Install as user systemd service (requires TOKEN and ENDPOINT)
install-user-service: build
	@if [ -z "$(TOKEN)" ] || [ -z "$(ENDPOINT)" ]; then \
		echo "Error: Please set TOKEN and ENDPOINT environment variables"; \
		echo "Example: make install-user-service TOKEN=pk_yourtoken ENDPOINT=https://your.domain.com"; \
		exit 1; \
	fi
	./$(BINARY_NAME) install --token=$(TOKEN) --endpoint=$(ENDPOINT) --user-mode

# Show version
version:
	@echo "$(VERSION)"

# Version management targets
version-get:
	@./version.sh get

version-bump-patch:
	@./version.sh bump patch

version-bump-minor:
	@./version.sh bump minor

version-bump-major:
	@./version.sh bump major

version-set:
	@if [ -z "$(V)" ]; then \
		echo "Error: Please specify version with V=x.y.z"; \
		echo "Example: make version-set V=1.2.3"; \
		exit 1; \
	fi
	@./version.sh set $(V)

# Development workflow
dev: fmt vet test build

# Generate checksums
checksums: build-all
	@echo "Generating checksums..."
	cd dist && sha256sum * > checksums.txt
	@echo "Checksums generated in dist/checksums.txt"

# Release workflow (build for all platforms)
release: clean fmt vet test dist build-all checksums
	@echo "Release build complete. Binaries and checksums in dist/"

# Show help
help:
	@echo "PubliKey Agent Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build           Build the binary"
	@echo "  build-all       Build for all supported platforms"
	@echo "  checksums       Generate SHA256 checksums for all binaries"
	@echo "  clean           Clean build artifacts"
	@echo "  fmt             Format Go code"
	@echo "  vet             Vet Go code"
	@echo "  test            Run tests"
	@echo "  deps            Install/update dependencies"
	@echo "  install         Install binary to /usr/local/bin (requires sudo)"
	@echo "  install-user    Install binary to ~/.local/bin"
	@echo "  install-service Install as systemd service (requires TOKEN and ENDPOINT)"
	@echo "  install-user-service Install as user systemd service (requires TOKEN and ENDPOINT)"
	@echo "  dry-run         Run agent in dry-run mode (requires TOKEN and ENDPOINT)"
	@echo "  dev             Run development workflow (fmt, vet, test, build)"
	@echo "  release         Create release build with checksums for all platforms"
	@echo ""
	@echo "Version Management:"
	@echo "  version         Show current version"
	@echo "  version-get     Get current version"
	@echo "  version-set     Set specific version (requires V=x.y.z)"
	@echo "  version-bump-patch   Bump patch version"
	@echo "  version-bump-minor   Bump minor version"
	@echo "  version-bump-major   Bump major version"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make install-service TOKEN=pk_abc123 ENDPOINT=https://demo.publikey.io"
	@echo "  make dry-run TOKEN=pk_abc123 ENDPOINT=https://demo.publikey.io"
	@echo "  make version-set V=1.0.0"
	@echo "  make release"