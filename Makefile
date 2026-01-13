IMAGE_NAME = ghcr.io/rachnog/cybergym-green-agent
TAG = latest

.PHONY: help build run stop clean test test-benchmark test-all

help:
	@echo "Available commands:"
	@echo "  make build          Build the Docker image"
	@echo "  make run            Run the Docker container (uses .env if present)"
	@echo "  make stop           Stop and remove the Docker container"
	@echo "  make clean          Remove the Docker image"
	@echo "  make test           Run core agent tests (requires local server)"
	@echo "  make test-benchmark Run standalone CyberGym benchmark tests"
	@echo "  make test-all       Run all tests"

build:
	docker build -t $(IMAGE_NAME):$(TAG) .

run:
	docker run -d --name cybergym-green-agent \
		$(shell [ -f .env ] && echo "--env-file .env") \
		-p 9009:9009 $(IMAGE_NAME):$(TAG)

stop:
	docker stop cybergym-green-agent || true
	docker rm cybergym-green-agent || true

clean:
	docker rmi $(IMAGE_NAME):$(TAG) || true

test:
	uv run pytest tests/test_agent.py -v

test-benchmark:
	uv run pytest tests/test_benchmark.py -v

test-all: test test-benchmark
