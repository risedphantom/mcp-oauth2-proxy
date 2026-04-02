.PHONY: build test clean docker-build docker-push lint fmt deps help version helm-debug

# Variables
BINARY_NAME=mcp-oauth2-proxy
DOCKER_IMAGE?=mcp-oauth2-proxy
DOCKER_TAG?=latest
HELM?=helm
GO_VERSION=1.24
VERSION?=1.0.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS=-ldflags "-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

# Default target
all: build

# Build the application
build:
	@echo "Building..."
	go build ${LDFLAGS} -o $(BINARY_NAME) ./cmd

# Run the server
serve: build
	@echo "Starting server..."
	./$(BINARY_NAME) serve --config config/config.example.yaml

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	@echo "Cleaning..."
	go clean
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Run linter
lint:
	@echo "Running linter..."
	@if ! which golangci-lint > /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
	fi
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	gofmt -s -w .

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Show version
version: build
	@./$(BINARY_NAME) version

# Debug Helm chart
helm-debug: ## Debug Helm chart.
	$(HELM) template -n mcp-oauth2-proxy mcp-oauth2-proxy deploy/helm --debug > deploy/helm/helm-debug.yaml

# Show help
help:
	@echo "Available targets:"
	@echo "  make build         - Build the application"
	@echo "  make serve         - Build and run the server"
	@echo "  make test          - Run tests"
	@echo "  make test-coverage - Run tests with coverage"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-push   - Push Docker image"
	@echo "  make lint          - Run linter"
	@echo "  make fmt           - Format code"
	@echo "  make deps          - Download dependencies"
	@echo "  make version       - Show version information"
	@echo "  make helm-debug    - Debug Helm chart"
	@echo "  make help          - Show this help message"
