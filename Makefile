VERSION := ${shell cat ./VERSION}
VERSION_FLAGS    := -ldflags='-X "main.Version=$(VERSION)"'

.PHONY: all
all: pal pald palpgpenc

.PHONY: pal
pal: dependencies bin
	GOOS=linux go build $(VERSION_FLAGS) -o bin/pal ./cmd/pal

.PHONY: pald
pald: dependencies bin
	GOOS=linux go build $(VERSION_FLAGS) -o bin/pald ./cmd/pald

.PHONY: palpgpenc
palpgpenc: dependencies bin
	GOOS=linux go build $(VERSION_FLAGS) -o bin/palpgpenc ./cmd/palpgpenc

.PHONY: test
test: platform-independent-tests platform-dependent-tests

.PHONY: platform-independent-tests
platform-independent-tests: dependencies
	@echo "Running platform-independent-tests"
	go test -race ./decrypter ./log

.PHONY: platform-dependent-tests
platform-dependent-tests: dependencies
	@echo "Running platform-dependent-tests"
	@if [ "$(shell uname -s)" != "Linux" ]; then echo "WARNING: Skipping Linux tests"; else \
		go test -race ./trustedlabels; \
		if which redoctober >/dev/null; then \
			go test -race; \
		else \
			echo "could not find 'redoctober' in PATH"; \
			exit 1; \
		fi \
	fi

.PHONY: integration-test
integration-test: pal pald
	@which redoctober >/dev/null || (echo "could not find 'redoctober' in PATH"; exit 1)
	@which docker-compose >/dev/null || (echo "could not find 'docker-compose' in PATH"; exit 1)
	cp $(shell which redoctober) bin
	./test/test.sh

.PHONY: clean
clean:
	rm -rf bin

.PHONY: bin
bin:
	mkdir -p bin

.PHONY: dependencies
dependencies:
	@which go >/dev/null || (echo "could not find 'go' in PATH"; exit 1)
