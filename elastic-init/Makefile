
DOCKER=docker
IMAGE=wisefood/elastic-init
# Bumped whenever the baked-in bundle changes, so a rollback is a tag change.
VERSION?=2026.08.25
IMGTAG=$(IMAGE):latest
IMGVER=$(IMAGE):$(VERSION)

.PHONY: all build push verify


all: verify build push

# Confirm the baked bundle is intact before it goes into an image.
verify:
	cd bundle && sha256sum --ignore-missing -c metadata/checksums.sha256

build:
	$(DOCKER) build . -t $(IMGTAG) -t $(IMGVER)

push:
	$(DOCKER) push $(IMGVER)
	$(DOCKER) push $(IMGTAG)
