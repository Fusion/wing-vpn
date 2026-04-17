BINARY := wing
DIST_DIR := dist
GOFLAGS :=

.PHONY: all clean test

all: macos linux

macos:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-arm64 .

linux:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(DIST_DIR)/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(DIST_DIR)/$(BINARY)-linux-arm64 .

clean:
	rm -rf $(DIST_DIR)

test:
	go test ./...
