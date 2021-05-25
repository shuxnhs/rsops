# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.


CLANG := clang
CLANG_INCLUDE := -I../

EBPF_SOURCE := ebpf_prog/sock_filter.c
EBPF_BINARY := ebpf_prog/sock_filter.elf

all: build_bpf 

build_bpf: $(EBPF_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

