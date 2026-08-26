PREFIX ?= $(HOME)/.local
DESTDIR ?=
CARGO ?= cargo
INSTALL ?= install

# rustup's default install is not always on PATH in non-login shells.
ifeq ($(CARGO),cargo)
ifneq ($(wildcard $(HOME)/.cargo/bin/cargo),)
CARGO := $(HOME)/.cargo/bin/cargo
endif
endif

.PHONY: all check-deps build install test test-scale

all: build

check-deps:
	@command -v "$(CARGO)" >/dev/null 2>&1 || { echo "error: Cargo is required; install Rust from https://rustup.rs/" >&2; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "error: Git is required; install it with your operating system package manager" >&2; exit 1; }
	@command -v findmnt >/dev/null 2>&1 || { echo "error: findmnt is required for safe storage discovery; install the util-linux package" >&2; exit 1; }
	@command -v "$(INSTALL)" >/dev/null 2>&1 || { echo "error: a POSIX-compatible install command is required (usually provided by coreutils)" >&2; exit 1; }

build: check-deps
	"$(CARGO)" build --release --locked

install: build
	"$(INSTALL)" -d "$(DESTDIR)$(PREFIX)/bin"
	"$(INSTALL)" -m 0755 target/release/archive "$(DESTDIR)$(PREFIX)/bin/archive"
	@echo "Installed archive to $(DESTDIR)$(PREFIX)/bin/archive"

# Routine development suite. Large acceptance gates are #[ignore]d by default.
test: check-deps
	"$(CARGO)" test --locked

# Explicit scale milestone; do not run on every feature iteration.
test-scale: check-deps
	"$(CARGO)" test --locked --test v2_scale_100k -- --ignored --nocapture --test-threads=1
