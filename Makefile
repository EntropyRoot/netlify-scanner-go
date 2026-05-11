BIN     ?= netlify-scanner-go
OUTDIR  ?= bin
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)
EXT     := $(if $(filter windows,$(GOOS)),.exe,)

.PHONY: build install clean tidy lint test release

build:
	@mkdir -p $(OUTDIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "-s -w" -o $(OUTDIR)/$(BIN)$(EXT) .

install:
	go install -trimpath -ldflags "-s -w" .

tidy:
	go mod tidy

lint:
	go vet ./...

test:
	go test ./... -count=1

clean:
	rm -rf $(OUTDIR) dist *.jsonl ips.txt sni-extra.txt

release:
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-windows-amd64.exe .
