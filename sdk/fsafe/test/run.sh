#!/usr/bin/env bash
set -euo pipefail

cd /src/sdk
ssh-keygen -A
go test -tags=policycontainer ./fsafe -run '^TestContainer_PolicyValidators$' -count=1
