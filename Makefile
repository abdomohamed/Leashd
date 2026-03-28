CLANG       ?= clang
BPF_CFLAGS  := -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign \
               -Wno-compare-distinct-pointer-types \
               -target bpf -D__TARGET_ARCH_x86
VMLINUX     := ebpf/headers/vmlinux.h
BINARY      := bin/leashd
CONNECTOR   := tests/e2e/helpers/connector/connector

.PHONY: all vmlinux generate build test test-int test-e2e test-all testbin clean lint

all: generate build

vmlinux:
	@echo "==> Generating vmlinux.h from host kernel BTF..."
	@mkdir -p ebpf/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "    $(VMLINUX) generated ($(shell wc -l < $(VMLINUX)) lines)"

generate: $(VMLINUX)
	@echo "==> Running go generate (bpf2go)..."
	go generate ./internal/bpf/...

build: generate
	@echo "==> Building leashd..."
	@mkdir -p bin
	CGO_ENABLED=0 go build \
	  -ldflags="-X github.com/abdotalema/leashd/internal/version.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
	  -o $(BINARY) ./cmd/leashd/
	@echo "    $(BINARY) built"

testbin:
	@echo "==> Building E2E test connector binary..."
	go build -o $(CONNECTOR) ./tests/e2e/helpers/connector/
	@echo "    $(CONNECTOR) built"

test:
	@echo "==> Running unit tests (no root required)..."
	go test ./internal/... -count=1 -timeout 60s

test-int:
	@echo "==> Running integration tests (requires root)..."
	go test -tags=integration ./internal/... -count=1 -timeout 120s -v

test-e2e: build testbin
	@echo "==> Running E2E tests (requires root + eBPF kernel)..."
	go test -tags=e2e ./tests/e2e/... -count=1 -timeout 300s -v

test-all: test test-int test-e2e

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) $(CONNECTOR)
	rm -f internal/bpf/leashd_bpf*.go internal/bpf/leashd_bpf*.o
