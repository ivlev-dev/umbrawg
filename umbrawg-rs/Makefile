.PHONY: all build release test clippy fmt bench clean

all: build

build:
	cargo build --workspace

release:
	cargo build --release --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all -- --check

bench:
	cargo bench -p umbrawg-bench

clean:
	cargo clean
