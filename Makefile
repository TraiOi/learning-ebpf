GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean

NAME := xdp_dump_eth_headers

CLANG := clang
CLANG_INCLUDE := -I${LIBH}

GO_SOURCE_EXAMPLES := ${GOPATH}/cmd/examples/main.go
GO_BINARY_EXAMPLES := ${GOBIN}/examples
GO_SOURCE := ${GOPATH}/cmd/shielder/main.go
GO_BINARY := ${GOPATH}/bin/shielder

C_SOURCE_EXAMPLES := ${LIBC}/examples/${NAME}.c
C_BINARY_EXAMPLES := ${LIBKO}/${NAME}.ko

examples: build_bpf_examples build_go_examples

build_bpf_examples: $(C_BINARY_EXAMPLES)

build_go_examples: $(GO_BINARY_EXAMPLES)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY_EXAMPLES)
	rm -f $(C_BINARY_EXAMPLES)

$(C_BINARY_EXAMPLES): $(C_SOURCE_EXAMPLES)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(GO_BINARY_EXAMPLES): $(GO_SOURCE_EXAMPLES)
	$(GOBUILD) -v -o $@ $^
