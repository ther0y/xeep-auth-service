# Build target
BINARY_NAME = xeep-auth-service
BINARY_PATH = ./target
BINARY = $(BINARY_PATH)/$(BINARY_NAME)

all: test build

build:
	go build -o $(BINARY) -v

test:
	go test -v ./...

clean:
	go clean
	rm -f $(BINARY)

run: build
	$(BINARY) --help

generate_grpc_code:
	protoc \
    --go_out=auther \
    --go_opt=paths=source_relative \
    --go-grpc_out=auther \
    --go-grpc_opt=paths=source_relative \
    auther.proto

.PHONY: all build test clean run
.DEFAULT_GOAL := run