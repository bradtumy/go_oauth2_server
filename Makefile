.PHONY: build run-as run-rs test test-exchange dev-up seed smoke

build:
	go build ./...

run-as:
	go run ./cmd/as

run-rs:
	go run ./cmd/rs

test:
	go test ./...

test-exchange:
	AS_BASE=${AS_BASE:-http://localhost:8080} RS_BASE=${RS_BASE:-http://localhost:9090} ./scripts/test_obo.sh

dev-up:
	docker compose up --build

seed:
	./scripts/seed_clients.sh

smoke:
	go test ./...
