#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A
go test -C /src/sdk -tags=policycontainer ./fsafe -run '^TestContainer_PolicyValidators$' -count=1 -race
