# Makefile for LANwatch

CARGO = cargo
RUSTDOCFLAGS = -D missing-docs

.PHONY: all build build-minimal release release-aarch64 release-aarch64-static test doc clean fmt fmt-check clippy check help examples

all: build test doc clippy

## update: Update dependencies list
update:
	$(CARGO) update

## build: Build the project with all features enabled
build: update
	$(CARGO) build --all-features

## build-minimal: Build the project with minimal default features
build-minimal: update
	$(CARGO) build --no-default-features

## release: Build the project in release mode with all features enabled
release: update
	$(CARGO) build --release --all-features

## release-aarch64: Cross-compile the release binary for ARM64 (aarch64-unknown-linux-gnu) using cross/docker
release-aarch64: update
	CROSS_ENV_PASSTHROUGH="CFLAGS RUSTFLAGS" CFLAGS="-w" RUSTFLAGS="" cross build --target aarch64-unknown-linux-gnu --release --all-features

## release-aarch64-static: Cross-compile the release binary for ARM64 (aarch64-unknown-linux-musl) using cross/docker
release-aarch64-static: update
	CROSS_ENV_PASSTHROUGH="CFLAGS RUSTFLAGS" CFLAGS="-w" RUSTFLAGS="" cross build --target aarch64-unknown-linux-musl --release --all-features

## test: Run unit tests with all features enabled
test:
	$(CARGO) test --all-features

## doc: Generate crate documentation with strict missing doc checks
doc:
	RUSTDOCFLAGS="$(RUSTDOCFLAGS)" $(CARGO) doc --no-deps --all-features

## clean: Clean the target directory
clean:
	$(CARGO) clean

## fmt: Format the codebase using rustfmt
fmt:
	$(CARGO) fmt --all

## fmt-check: Check if codebase is formatted
fmt-check:
	$(CARGO) fmt --all -- --check

## clippy: Lint the project with clippy with warnings treated as errors
clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

## check: Check codebase quickly
check:
	$(CARGO) check --all-features

## examples: Build all example binaries with all features enabled
examples:
	$(CARGO) build --examples --all-features

## help: Show this help message
help:
	@echo "Available Makefile targets:"
	@grep -h "##" $(MAKEFILE_LIST) | grep -v grep | sed -e 's/## //'
