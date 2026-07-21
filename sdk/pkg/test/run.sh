#!/bin/sh
set -eu

: "${PM_PKG_BACKEND:?PM_PKG_BACKEND is required}"
cd /src/sdk
go test -tags=container ./pkg ./rollback -count=1
