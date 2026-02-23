.PHONY: all server client clean test clippy fmt release deploy-server

RELEASE_DIR := releases/latest

all: test clippy server client

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings


fmt:
	cargo fmt --all

server:
	cargo zigbuild --release -p arps --target x86_64-unknown-linux-gnu

client:
	cargo zigbuild --release -p arpc --target x86_64-unknown-linux-gnu
	cargo zigbuild --release -p arpc --target aarch64-unknown-linux-gnu

release: test clippy server client
	mkdir -p $(RELEASE_DIR)
	cp target/x86_64-unknown-linux-gnu/release/arps $(RELEASE_DIR)/arps-linux-x86_64
	cp target/x86_64-unknown-linux-gnu/release/arpc $(RELEASE_DIR)/arpc-linux-x86_64
	cp target/aarch64-unknown-linux-gnu/release/arpc $(RELEASE_DIR)/arpc-linux-aarch64
	@echo ""
	@echo "Release binaries:"
	@ls -lh $(RELEASE_DIR)/
	@echo ""
	@echo "Note: macOS binaries require building on macOS or via CI with macOS SDK."

deploy-server: server
	sudo systemctl stop arps
	sudo cp target/x86_64-unknown-linux-gnu/release/arps /opt/arp/arps
	sudo systemctl start arps

clean:
	cargo clean
