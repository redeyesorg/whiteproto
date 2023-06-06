#!/usr/bin/env bash

set -o errexit

# Change directory to the project root directory.
cd "$(dirname "$0")"

poetry run mypy --config-file mypy.ini whiteproto
