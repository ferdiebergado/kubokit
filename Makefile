# Project Name
PROJECT_NAME = kubokit

# Binary Name
BINARY_NAME = $(PROJECT_NAME)

# Go Modules Path
GO_MODULE_PATH = ./...

# Build Directory
BUILD_DIR = build

# Versioning
VERSION = v0.0.1

# Go Flags
GO_FLAGS = -race -v

# Container runtime
CONTAINER_RUNTIME := $(shell if command -v podman >/dev/null 2>&1; \
then echo podman; \
elif command -v docker >/dev/null 2>&1; \
then echo docker; \
else echo ""; \
fi)

# Container of the postgres database
DB_CONTAINER := kubokitdb
DB_IMAGE := postgres:17.0-alpine3.20

# Path for db migrations
MIGRATIONS_DIR := ./db/migrations

# Env
ENV ?= development

ifeq ($(ENV),development)
	ENV_FILE = ./.env
endif

ifeq ($(ENV),testing)
	ENV_FILE = ./.env.testing
endif

.PHONY: $(wildcard *)

%:
	@true

## default: Show usage information
default:
	@echo "TARGET          DESCRIPTION                          		  EXAMPLE"
	@echo "-----------------------------------------------------------------------------------------------------"
	@sed -n 's/^## //p' Makefile | column -t -s ':'

## dev: Run the project in development mode
dev: migrate-up
	@command -v air >/dev/null || go install github.com/air-verse/air@latest
	@air

## build: Build the project
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GO_FLAGS) -ldflags="-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server/...
	@echo "Build complete!"

## run: Run the project
run: build db
	@echo "Running $(BINARY_NAME) $(VERSION)..."
	@$(BUILD_DIR)/$(BINARY_NAME)

## test: Run the unit tests: make test ENV=testing
test: migrate-up
	@echo "Running unit tests..."
	@go test $(GO_FLAGS) $(GO_MODULE_PATH)

## test-integration: Run the integration tests: make test-integration ENV=testing
test-integration: migrate-up
	@echo "Running integration tests..."
	@go test $(GO_FLAGS) -run Integration $(GO_MODULE_PATH)

test-cover: test
	@go tool cover -html=coverage.out

docker-check:
	@if [ -z "$(CONTAINER_RUNTIME)" ]; then \
		echo "No container runtime found (docker or podman)."; \
		exit 1; \
	fi
	@if [ "$(CONTAINER_RUNTIME)" = "docker" ]; then \
		if ! docker info >/dev/null 2>&1; then \
			echo "Docker is NOT running.  Please start it."; \
			exit 1; \
		fi; \
	fi
	@echo "Detected container runtime is $(CONTAINER_RUNTIME)."

docker-build:
	@echo "Building Docker image..."
	@docker build -t $(PROJECT_NAME):$(VERSION) .

docker-run:
	@echo "Running Docker container..."
	@docker run -p 8080:8080 $(PROJECT_NAME):$(VERSION)

## db: Start the database container
db: docker-check
	@if ! $(CONTAINER_RUNTIME) ps | grep -q $(DB_CONTAINER); then \
		echo "Starting database container..."; \
		set -a; . $(ENV_FILE); set +a; \
		$(CONTAINER_RUNTIME) run --rm \
		-e POSTGRES_USER=$$DB_USER -e POSTGRES_PASSWORD=$$DB_PASS -e POSTGRES_DB=$$DB_NAME \
		-p 5432:5432 \
		-v ./configs/postgresql/postgresql.conf:/etc/postgresql/postgresql.conf:Z \
		-v ./configs/postgresql/psqlrc:/root/.psqlrc:Z \
		--name $(DB_CONTAINER) -d $(DB_IMAGE) \
		-c 'config_file=/etc/postgresql/postgresql.conf'; \
		sleep 5s; \
	else \
		echo "Database container $(DB_CONTAINER) is already running."; \
	fi

## psql: Open a session with the database instance
psql: db
	@set -a; . $(ENV_FILE); set +a; \
	$(CONTAINER_RUNTIME) exec -it $(DB_CONTAINER) psql -U $$DB_USER $$DB_NAME

lint:
	@echo "Running golangci-lint..."
	@command -v golangci-lint>/dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.63.4
	@golangci-lint run $(GO_MODULE_PATH)

format:
	@echo "Running go fmt..."
	@go fmt $(GO_MODULE_PATH)

migrate-check:
	@command -v migrate>/dev/null || go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

## migrate-new: Create a new migration: make migrate-new create_users_table
migrate-new: migrate-check
	@migrate create -dir $(MIGRATIONS_DIR) -ext sql -seq $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))

## migrate-up: Run the database migrations
migrate-up: migrate-check db
	@echo "Running database migrations..."
	@set -a; . $(ENV_FILE); set +a; \
	migrate -path $(MIGRATIONS_DIR) -database "postgres://$$DB_USER:$$DB_PASS@localhost:5432/$$DB_NAME?sslmode=$$DB_SSLMODE" up
	@echo "Database migration completed."

## migrate-down: Rollback the database migrations
migrate-down: migrate-check db
	@echo "Rolling back database migrations..."
	@set -a; . $(ENV_FILE); set +a; \
	migrate -path $(MIGRATIONS_DIR) -database "postgres://$$DB_USER:$$DB_PASS@localhost:5432/$$DB_NAME?sslmode=$$DB_SSLMODE" down
	@echo "Database migrations rollback complete."

## migrate-force: Force a migration: make migrate-force 1
migrate-force:
	@echo "Forcing migration..."
	@set -a; . $(ENV_FILE); set +a; \
	migrate -path $(MIGRATIONS_DIR) -database "postgres://$$DB_USER:$$DB_PASS@localhost:5432/$$DB_NAME?sslmode=$$DB_SSLMODE" force $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))

## migrate-drop: Drop all tables in the database
migrate-drop: migrate-check db
	@echo "Dropping all database tables..."
	@set -a; . $(ENV_FILE); set +a; \
	migrate -path $(MIGRATIONS_DIR) -database "postgres://$$DB_USER:$$DB_PASS@localhost:5432/$$DB_NAME?sslmode=$$DB_SSLMODE" drop
	@echo "Dropped database tables."

## gen: Generate source files
gen:
	@echo "Generating sources..."
	@command -v mockgen >/dev/null || go install go.uber.org/mock/mockgen@latest
	@go generate -v $(GO_MODULE_PATH)
	@echo "Sources generated"

## tidy: Add missing/Remove unused modules
tidy:
	@echo "Adding/removing modules..."
	@go mod tidy

## update: Update dependencies
update:
	@echo "Updating dependencies..."
	@go get -u $(GO_MODULE_PATH)
	@echo "Update complete."

## vulncheck: Check for known vulnerabilities in dependencies
vulncheck:
	@echo "Running govulncheck..."
	@command -v govulncheck>/dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
	@govulncheck $(GO_MODULE_PATH)

## sec: Check for security issues
sec:
	@echo "Running gosec..."
	@command -v gosec>/dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@gosec $(GO_MODULE_PATH)

## check: Check modules for updates
check:
	@echo "Checking for module updates..."
	@go list -m -u all

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out
	@echo "Clean complete!"

## app-key: Generate a new app key
app-key:
	@sed -i "s/^KEY=.*/KEY=$$(openssl rand -base64 64 | tr -d '\n' | sed 's/\//_/g')/" .env

## mailhog: Starts mailhog smtp server
mailhog:
	@echo "Starting mailhog..."
	@$(CONTAINER_RUNTIME) run --rm --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog

prod:
	@GO_FLAGS=-ldflags="-s -w"
	@ENV=production
	@$(MAKE) run
