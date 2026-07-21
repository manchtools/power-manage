.PHONY: sqlc-generate sqlc-check

SQLC_IMAGE ?= sqlc/sqlc:1.30.0

sqlc-generate:
	cd internal/store && docker run --rm \
		--user "$$(id -u):$$(id -g)" \
		-v "$$(pwd):/src:Z" -w /src $(SQLC_IMAGE) generate

# docref: begin sqlc-check
sqlc-check:
	@set -eu; \
	generated="$$(mktemp -d)"; \
	trap 'rm -rf "$$generated"' EXIT; \
	cp internal/store/sqlc.yaml "$$generated/"; \
	cp -R internal/store/migrations internal/store/queries "$$generated/"; \
	docker run --rm --user "$$(id -u):$$(id -g)" \
		-v "$$generated:/src:Z" -w /src $(SQLC_IMAGE) generate; \
	diff -ru internal/store/generated "$$generated/generated"
# docref: end sqlc-check
