.PHONY: build run test clean docker-up docker-down migrate

# Variables
APP_NAME=auth-system
BINARY_NAME=main
DOCKER_COMPOSE_FILE=docker-compose.yml

# Build the application
build:
	go build -o bin/$(BINARY_NAME) cmd/main.go

# Run the application
run:
	go run cmd/main.go

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Install dependencies
deps:
	go mod download
	go mod tidy

# Run with hot reload (requires air: go install github.com/cosmtrek/air@latest)
dev:
	air

# Docker commands
docker-build:
	docker build -t $(APP_NAME) .

docker-run:
	docker run -p 8080:8080 $(APP_NAME)

docker-up:
	docker-compose -f $(DOCKER_COMPOSE_FILE) up -d

docker-down:
	docker-compose -f $(DOCKER_COMPOSE_FILE) down

docker-logs:
	docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f

# Database commands
db-create:
	createdb authdb

db-drop:
	dropdb authdb

# Lint the code (requires golangci-lint)
lint:
	golangci-lint run

# Format the code
fmt:
	go fmt ./...

# Generate mocks (if using mockery)
generate-mocks:
	mockery --all --keeptree