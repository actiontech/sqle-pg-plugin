override GIT_VERSION    		= $(shell git rev-parse --abbrev-ref HEAD)${CUSTOM} $(shell git rev-parse HEAD)
override PROJECT_NAME 			= sqle-pg-plugin
override LDFLAGS 				= -ldflags "-X 'main.version=\"${GIT_VERSION}\"'"
override GOBIN					= ${shell pwd}/bin

# Copy from SQLE
PROJECT_VERSION = $(shell if [ "$$(git tag --points-at HEAD | tail -n1)" ]; then git tag --points-at HEAD | tail -n1 | sed 's/v\(.*\)/\1/'; else git rev-parse --abbrev-ref HEAD | sed 's/release-\(.*\)/\1/' | tr '-' '\n' | head -n1; fi)

default: install

install:
	go build -mod=vendor ${LDFLAGS} -o $(GOBIN)/$(PROJECT_NAME) ./

upload:
	curl -T $(shell pwd)/$(GOBIN)/$(PROJECT_NAME) ftp://$(RELEASE_FTPD_HOST)/actiontech-sqle/plugins/$(PROJECT_VERSION)/$(PROJECT_NAME) --ftp-create-dirs

.PHONY: vendor
vendor:
	go mod vendor
	modvendor -copy="**/*.c **/*.h" -v	