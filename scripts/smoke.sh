#!/bin/sh
set -eu

echo "== Rotation status =="
releasectl incident

echo "== Trusted metadata =="
releasectl metadata

echo "== amd64 =="
releasectl admit linux/amd64

echo "== arm64 =="
releasectl admit linux/arm64

echo "== Root chain =="
rootctl verify-chain
