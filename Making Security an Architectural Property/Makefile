.PHONY: help build run stop policy scan clean

help:
	@echo "Targets:"
	@echo "  make build      Build both baseline and hardened images"
	@echo "  make run        Run the hardened container locally on :8080"
	@echo "  make policy     Run OPA/Conftest policy on both Dockerfiles"
	@echo "  make scan       Run Trivy CVE scan on both images"
	@echo "  make stop       Stop running demo containers"
	@echo "  make clean      Remove demo images"

build:
	docker build -t demo/nginx-baseline:local -f Dockerfile.baseline .
	docker build -t demo/nginx-hardened:local -f Dockerfile.hardened .

run: build
	docker compose up -d hardened
	@echo "Hardened nginx running at http://localhost:8080"

policy:
	@echo "--- Baseline (expect FAIL) ---"
	-conftest test --policy policies/ Dockerfile.baseline
	@echo ""
	@echo "--- Hardened (expect PASS) ---"
	conftest test --policy policies/ Dockerfile.hardened

scan: build
	@echo "--- Baseline ---"
	-trivy image --severity HIGH,CRITICAL --scanners vuln demo/nginx-baseline:local
	@echo ""
	@echo "--- Hardened ---"
	-trivy image --severity HIGH,CRITICAL --scanners vuln demo/nginx-hardened:local

stop:
	-docker compose down

clean: stop
	-docker rmi demo/nginx-baseline:local demo/nginx-hardened:local