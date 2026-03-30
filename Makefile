APP_NAME := alt-hardening-scanner
VERSION := 1.0.0
TOPDIR := $(CURDIR)/build/rpmbuild
TARBALL := $(TOPDIR)/SOURCES/$(APP_NAME)-$(VERSION).tar.gz

.PHONY: all build check fmt archive rpm clean

all: build

build:
	cargo build --release

check:
	cargo check

fmt:
	cargo fmt

archive:
	mkdir -p $(TOPDIR)/SOURCES $(TOPDIR)/SPECS
	git archive --format=tar.gz --output=$(TARBALL) --prefix=$(APP_NAME)-$(VERSION)/ HEAD
	cp rpm/$(APP_NAME).spec $(TOPDIR)/SPECS/

rpm: archive
	rpmbuild -bb --define "_topdir $(TOPDIR)" $(TOPDIR)/SPECS/$(APP_NAME).spec

clean:
	rm -rf target
