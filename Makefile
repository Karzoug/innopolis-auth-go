BUILD_DIR ?= bin
BUILD_PACKAGE ?= ./cmd/main.go
PROJECT_PKG = github.com/Karzoug/innopolis-auth-go
LOCAL_BIN:=$(CURDIR)/bin
BINARY_NAME = auth

VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || git symbolic-ref -q --short HEAD)
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
# remove debug info from the binary & make it smaller
LDFLAGS += -s -w
LDFLAGS += -X ${PROJECT_PKG}/internal/buildinfo.version=${VERSION} -X ${PROJECT_PKG}/internal/buildinfo.commitHash=${COMMIT_HASH} -X ${PROJECT_PKG}/internal/buildinfo.buildDate=${BUILD_DATE}

build:
	go build ${GOARGS} -tags "${GOTAGS}" -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/${BINARY_NAME} ${BUILD_PACKAGE}

install-deps:
	GOBIN=$(LOCAL_BIN) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.3.0

generate:
	$(LOCAL_BIN)/oapi-codegen --config=oapi_server.config.yaml docs/swagger.yaml
	$(LOCAL_BIN)/oapi-codegen --config=oapi_models.config.yaml docs/swagger.yaml