BINARY      := nnp-quantum-safe-service
CMD         := ./cmd/server
IMAGE_NAME  := picc-pc-quantum-safe-service
TAG         := latest

.PHONY: help build run test test-race vet format tidy clean docker-build docker-run compose-up compose-down sbom

help:
	@echo "Available targets:"
	@echo "  build         - Compile the Go microservice binary"
	@echo "  run           - Build and execute locally"
	@echo "  test          - Run standard unit test suite"
	@echo "  test-race     - Run unit test suite with race condition detection"
	@echo "  vet           - Run Go static code analysis (go vet)"
	@echo "  format        - Format Go source code (go fmt)"
	@echo "  tidy          - Tidy and verify go.mod and go.sum dependencies"
	@echo "  clean         - Remove compiled binary and test coverage artifacts"
	@echo "  docker-build  - Build production-ready Docker container image"
	@echo "  docker-run    - Run container locally with persistent key volume"
	@echo "  compose-up    - Start local stack via Docker Compose"
	@echo "  compose-down  - Stop local Docker Compose stack"
	@echo "  sbom          - Generate CycloneDX SBOM"

build:
	go build -o $(BINARY) $(CMD)

run: build
	./$(BINARY)

test:
	go test -v ./...

test-race:
	go test -v -race ./...

vet:
	go vet ./...

format:
	go fmt ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(BINARY).exe coverage.out coverage.html bom.json

docker-build:
	docker build -t $(IMAGE_NAME):$(TAG) .

docker-run:
	docker run -d --name $(IMAGE_NAME) -p 8080:8080 -v "$$(pwd)/keys:/app/keys" $(IMAGE_NAME):$(TAG)

compose-up:
	docker compose up -d

compose-down:
	docker compose down

sbom:
	cyclonedx-gomod app -json -output bom.json -main cmd/server .
