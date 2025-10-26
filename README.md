# kubokit

[![CodeQL](https://github.com/ferdiebergado/kubokit/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ferdiebergado/kubokit/actions/workflows/github-code-scanning/codeql)
[![Go Report Card](https://goreportcard.com/badge/github.com/ferdiebergado/kubokit)](https://goreportcard.com/report/github.com/ferdiebergado/kubokit)

A REST API starter kit with straightforward approach and minimal dependencies.

## Requirements

-   Go 1.23 or higher
-   docker or podman

## Quick Start

1. [Create a repository from the template](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template#creating-a-repository-from-a-template).

```bash
gh repo create my-rest-api --template ferdiebergado/kubokit --public --clone
```

2. Rename .env.example to .env and update the values based on your environment.

```bash
mv .env.example .env
```

3. Generate an app key.

```bash
make app-key
```

4. Run the api in development mode.

```bash
make dev
```

5. Send requests to the api at [localhost:8888](http://localhost:8888).

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"email": "abc@example.com", "password": "test"}' localhost:8888/auth/login
```

## Running Tests

Create a .env.testing file by copying .env.

```bash
cp .env .env.testing
```

Update the values according to your testing environment.

### Unit Tests

To run unit tests, run the following command:

```bash
make test ENV=testing
```

### Integration Tests

To run integration tests, run the following command:

```bash
make test-integration ENV=testing
```

## Tasks

Common development tasks are captured in the Makefile. To view those tasks, run the following command:

```bash
make
```

If a required tool is missing, it will be automatically installed.
