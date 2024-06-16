# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = packetBroker

# all source are stored in SRCS-pb
SRCS-pb := packetBroker.c

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: static stats logs
.PHONY: shared static logs
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)
stats:
	@mkdir -p $@
logs:
	@mkdir -p $@

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk libhs)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk libhs)
LDFLAGS_NETWORK = $(shell echo -lcurl -ljansson)

ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP)-shared: $(SRCS-pb) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-pb) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) $(LDFLAGS_NETWORK)

build/$(APP)-static: $(SRCS-pb) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-pb) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC) $(LDFLAGS_NETWORK)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build && rm -rf stats || true
