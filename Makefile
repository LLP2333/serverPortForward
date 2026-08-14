APP := server-port-forward
DIST := dist
GO_CACHE := /tmp/serverportforward-gocache
LDFLAGS := -s -w -H=windowsgui

.PHONY: all test vet build build-amd64 build-arm64 clean

all: test build

test:
	mkdir -p $(GO_CACHE)
	GOCACHE=$(GO_CACHE) go test ./...

vet:
	mkdir -p $(GO_CACHE)
	GOCACHE=$(GO_CACHE) go vet ./...

build: build-amd64 build-arm64

build-amd64:
	mkdir -p $(DIST) $(GO_CACHE)
	GOCACHE=$(GO_CACHE) CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(APP)-windows-amd64.exe .

build-arm64:
	mkdir -p $(DIST) $(GO_CACHE)
	GOCACHE=$(GO_CACHE) CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(APP)-windows-arm64.exe .

clean:
	rm -rf $(DIST)
