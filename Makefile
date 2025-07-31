# Universal AI Governor Makefile
# Supports cross-platform builds for any OS and architecture

.PHONY: all build clean test lint docker install uninstall help

# Build configuration
BINARY_NAME := ai-governor
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT) -w -s"
BUILD_FLAGS := -trimpath $(LDFLAGS)

# Directories
BUILD_DIR := build
DIST_DIR := dist
DOCKER_DIR := docker

# Supported platforms
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

# Docker platforms
DOCKER_PLATFORMS := linux/amd64,linux/arm64

# Default target
all: build

# Build for current platform
build:
	@echo "Building $(BINARY_NAME) $(VERSION) for current platform..."
	@mkdir -p $(BUILD_DIR)
	go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/main.go
	@echo "Build completed: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for all platforms
build-all: clean
	@echo "Building $(BINARY_NAME) $(VERSION) for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		output_name=$(BINARY_NAME); \
		if [ $$os = "windows" ]; then output_name=$(BINARY_NAME).exe; fi; \
		echo "Building for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(BUILD_FLAGS) \
			-o $(DIST_DIR)/$(BINARY_NAME)-$$os-$$arch/$$output_name ./cmd/main.go; \
		if [ $$? -ne 0 ]; then \
			echo "Failed to build for $$os/$$arch"; \
			exit 1; \
		fi; \
		cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-$$os-$$arch.tar.gz $(BINARY_NAME)-$$os-$$arch/ && cd ..; \
	done
	@echo "Cross-compilation completed. Artifacts in $(DIST_DIR)/"

# Build for specific platform
build-platform:
	@if [ -z "$(PLATFORM)" ]; then \
		echo "Usage: make build-platform PLATFORM=os/arch"; \
		echo "Example: make build-platform PLATFORM=linux/amd64"; \
		exit 1; \
	fi
	@os=$$(echo $(PLATFORM) | cut -d'/' -f1); \
	arch=$$(echo $(PLATFORM) | cut -d'/' -f2); \
	output_name=$(BINARY_NAME); \
	if [ $$os = "windows" ]; then output_name=$(BINARY_NAME).exe; fi; \
	echo "Building for $$os/$$arch..."; \
	mkdir -p $(BUILD_DIR); \
	GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(BUILD_FLAGS) \
		-o $(BUILD_DIR)/$$output_name ./cmd/main.go

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Test coverage report: coverage.html"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Lint code
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Installing..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		golangci-lint run; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	go mod tidy
	go mod verify

# Generate code
generate:
	@echo "Generating code..."
	go generate ./...

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t universal-ai-governor:$(VERSION) .
	docker tag universal-ai-governor:$(VERSION) universal-ai-governor:latest

# Build multi-platform Docker images
docker-buildx:
	@echo "Building multi-platform Docker images..."
	docker buildx create --use --name multiarch-builder 2>/dev/null || true
	docker buildx build \
		--platform $(DOCKER_PLATFORMS) \
		--tag universal-ai-governor:$(VERSION) \
		--tag universal-ai-governor:latest \
		--push .

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run -d \
		--name ai-governor \
		-p 8080:8080 \
		-p 9090:9090 \
		-v $(PWD)/configs:/app/configs:ro \
		-v $(PWD)/policies:/app/policies:ro \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/logs:/app/logs \
		universal-ai-governor:latest

# Stop Docker container
docker-stop:
	@echo "Stopping Docker container..."
	docker stop ai-governor 2>/dev/null || true
	docker rm ai-governor 2>/dev/null || true

# Build Debian package
deb: build-platform
	@echo "Building Debian package..."
	@mkdir -p $(BUILD_DIR)/deb/DEBIAN
	@mkdir -p $(BUILD_DIR)/deb/usr/local/bin
	@mkdir -p $(BUILD_DIR)/deb/etc/ai-governor
	@mkdir -p $(BUILD_DIR)/deb/var/lib/ai-governor
	@mkdir -p $(BUILD_DIR)/deb/var/log/ai-governor
	@mkdir -p $(BUILD_DIR)/deb/etc/systemd/system
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(BUILD_DIR)/deb/usr/local/bin/
	@cp configs/config.yaml $(BUILD_DIR)/deb/etc/ai-governor/
	@cp -r policies $(BUILD_DIR)/deb/etc/ai-governor/
	@cp scripts/ai-governor.service $(BUILD_DIR)/deb/etc/systemd/system/
	@cat > $(BUILD_DIR)/deb/DEBIAN/control << EOF
Package: universal-ai-governor
Version: $(VERSION)
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Universal AI Governor Team <team@example.com>
Description: Universal AI Governance Module
 A comprehensive AI governance system that can be deployed across
 any operating system and device with policy enforcement, moderation,
 and audit capabilities.
EOF
	@dpkg-deb --build $(BUILD_DIR)/deb $(DIST_DIR)/universal-ai-governor_$(VERSION)_amd64.deb

# Build RPM package
rpm: build-platform
	@echo "Building RPM package..."
	@mkdir -p $(BUILD_DIR)/rpm/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@mkdir -p $(BUILD_DIR)/rpm/BUILD/usr/local/bin
	@mkdir -p $(BUILD_DIR)/rpm/BUILD/etc/ai-governor
	@mkdir -p $(BUILD_DIR)/rpm/BUILD/var/lib/ai-governor
	@mkdir -p $(BUILD_DIR)/rpm/BUILD/var/log/ai-governor
	@mkdir -p $(BUILD_DIR)/rpm/BUILD/etc/systemd/system
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(BUILD_DIR)/rpm/BUILD/usr/local/bin/
	@cp configs/config.yaml $(BUILD_DIR)/rpm/BUILD/etc/ai-governor/
	@cp -r policies $(BUILD_DIR)/rpm/BUILD/etc/ai-governor/
	@cp scripts/ai-governor.service $(BUILD_DIR)/rpm/BUILD/etc/systemd/system/
	@cat > $(BUILD_DIR)/rpm/SPECS/universal-ai-governor.spec << EOF
Name: universal-ai-governor
Version: $(VERSION)
Release: 1
Summary: Universal AI Governance Module
License: MIT
Group: Applications/System
BuildArch: x86_64

%description
A comprehensive AI governance system that can be deployed across
any operating system and device with policy enforcement, moderation,
and audit capabilities.

%files
/usr/local/bin/$(BINARY_NAME)
/etc/ai-governor/config.yaml
/etc/ai-governor/policies/
/etc/systemd/system/ai-governor.service
%dir /var/lib/ai-governor
%dir /var/log/ai-governor

%post
systemctl daemon-reload
systemctl enable ai-governor

%preun
systemctl stop ai-governor
systemctl disable ai-governor

%postun
systemctl daemon-reload
EOF
	@rpmbuild --define "_topdir $(PWD)/$(BUILD_DIR)/rpm" -bb $(BUILD_DIR)/rpm/SPECS/universal-ai-governor.spec
	@cp $(BUILD_DIR)/rpm/RPMS/x86_64/*.rpm $(DIST_DIR)/

# Install locally
install: build
	@echo "Installing $(BINARY_NAME)..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/; \
		mkdir -p /etc/ai-governor /var/lib/ai-governor /var/log/ai-governor; \
		cp configs/config.yaml /etc/ai-governor/; \
		cp -r policies /etc/ai-governor/; \
		echo "Installed to /usr/local/bin/$(BINARY_NAME)"; \
	else \
		mkdir -p $$HOME/.local/bin; \
		cp $(BUILD_DIR)/$(BINARY_NAME) $$HOME/.local/bin/; \
		mkdir -p $$HOME/.config/ai-governor $$HOME/.local/share/ai-governor; \
		cp configs/config.yaml $$HOME/.config/ai-governor/; \
		cp -r policies $$HOME/.config/ai-governor/; \
		echo "Installed to $$HOME/.local/bin/$(BINARY_NAME)"; \
		echo "Make sure $$HOME/.local/bin is in your PATH"; \
	fi

# Uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@rm -f $$HOME/.local/bin/$(BINARY_NAME)
	@echo "Uninstalled $(BINARY_NAME)"

# Development server
dev: build
	@echo "Starting development server..."
	@./$(BUILD_DIR)/$(BINARY_NAME) --config configs/config.yaml

# Production deployment
deploy: docker
	@echo "Deploying to production..."
	docker-compose -f docker-compose.prod.yml up -d

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR) coverage.out coverage.html
	@docker rmi universal-ai-governor:$(VERSION) universal-ai-governor:latest 2>/dev/null || true

# Security scan
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Installing..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
		gosec ./...; \
	fi

# Dependency check
deps-check:
	@echo "Checking dependencies for vulnerabilities..."
	@if command -v nancy >/dev/null 2>&1; then \
		go list -json -m all | nancy sleuth; \
	else \
		echo "nancy not found. Installing..."; \
		go install github.com/sonatypecommunity/nancy@latest; \
		go list -json -m all | nancy sleuth; \
	fi

# Release preparation
release: clean lint test security build-all
	@echo "Preparing release $(VERSION)..."
	@echo "Release artifacts ready in $(DIST_DIR)/"

# Show help
help:
	@echo "Universal AI Governor Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build          Build for current platform"
	@echo "  build-all      Build for all supported platforms"
	@echo "  build-platform Build for specific platform (use PLATFORM=os/arch)"
	@echo "  test           Run tests with coverage"
	@echo "  bench          Run benchmarks"
	@echo "  lint           Run code linters"
	@echo "  fmt            Format code"
	@echo "  tidy           Tidy dependencies"
	@echo "  generate       Generate code"
	@echo "  docker         Build Docker image"
	@echo "  docker-buildx  Build multi-platform Docker images"
	@echo "  docker-run     Run Docker container"
	@echo "  docker-stop    Stop Docker container"
	@echo "  deb            Build Debian package"
	@echo "  rpm            Build RPM package"
	@echo "  install        Install locally"
	@echo "  uninstall      Uninstall"
	@echo "  dev            Start development server"
	@echo "  deploy         Deploy to production"
	@echo "  clean          Clean build artifacts"
	@echo "  security       Run security scan"
	@echo "  deps-check     Check dependencies for vulnerabilities"
	@echo "  release        Prepare release (lint, test, build-all)"
	@echo "  help           Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  PLATFORM       Target platform for build-platform (e.g., linux/amd64)"
	@echo "  VERSION        Override version (default: git describe)"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make build-platform PLATFORM=linux/arm64"
	@echo "  make docker"
	@echo "  make release"
