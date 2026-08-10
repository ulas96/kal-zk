# `set -a` exports what .env defines; plain `.` will not, and os.Getenv sees nothing.
ENV = if [ -f ./.env ]; then set -a; . ./.env; set +a; fi
KAL_REPO ?= ../kal

.PHONY: help test test-db test-audit lint fmt vet cover audit bench-zk mutation-zk release-check check

help:
	@echo "test     go test ./...            (the TestDB* tests SKIP — see test-db)"
	@echo "test-db  same, with .env exported (the TestDB* tests run)"
	@echo "test-audit DB suite plus zkaudit-only entropy, saturation, TTL and timing tests"
	@echo "lint     golangci-lint run"
	@echo "fmt      gofmt -w ."
	@echo "vet      go vet ./..."
	@echo "cover    coverage profile + summary"
	@echo "audit    govulncheck + gosec"
	@echo "bench-zk one valid prove/verify measurement for each circuit"
	@echo "mutation-zk run the pinned 55-mutation manifest in isolated source snapshots"
	@echo "release-check all stable-release gates; requires RELEASE_TAG=vX.Y.Z"
	@echo "check    fmt check + vet + lint + test-db + audit"

test:
	go test ./...

# The only run that proves anything: the TestDB* tests skip silently without DATABASE_URL, and a
# skipped test still reports ok. In this library that silence would cover session revocation,
# token single-use and the unique index — the things a green run is assumed to have proven.
# -v so you can see that they ran.
test-db:
	@$(ENV); bash scripts/check-db-tests.sh

test-audit:
	@$(ENV); bash scripts/check-db-tests.sh zkaudit
	@$(ENV); go test -tags zkaudit -race -count=1 -timeout 45m ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

vet:
	go vet ./...

cover:
	$(ENV) && go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

# An auth library that does not scan its own dependency graph is asking every consumer to do it
# instead (luima's security review calls the missing gate B-01). Pinned to @latest deliberately:
# a vulnerability scanner frozen at an old version stops knowing about new vulnerabilities.
#
# govulncheck also reports standard-library vulnerabilities against the toolchain that built the
# code, so this fails on an out-of-date local Go even when kal and its dependencies are clean.
# That is the tool working: upgrade Go rather than suppressing it.
audit:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

bench-zk:
	go test -run '^TestZKCircuitID$$' -v ./tests
	go test -run '^$$' -bench '^BenchmarkZK(Knowledge|Membership)$$' -benchtime=1x -count=1 ./tests

mutation-zk:
	@$(ENV); go run ./internal/cmd/zktestmutate -manifest tests/zk_mutations.json -kal-repo "$(KAL_REPO)"

release-check:
	@test -n "$(RELEASE_TAG)" || { echo "RELEASE_TAG=vX.Y.Z is required"; exit 1; }
	@test -z "$$(git rev-parse --is-shallow-repository | grep true)" || { echo "full git history is required"; exit 1; }
	@test -z "$$(git status --porcelain=v1 --untracked-files=all)" || { echo "release requires a clean committed worktree"; exit 1; }
	@test -z "$$(grep -n '^replace ' go.mod)" || { echo "go.mod contains a release-blocking replace directive"; exit 1; }
	git verify-tag "$(RELEASE_TAG)"
	@$(MAKE) check
	@$(MAKE) test-audit
	@$(MAKE) bench-zk
	@$(MAKE) mutation-zk

check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) test-db
	@$(MAKE) audit
