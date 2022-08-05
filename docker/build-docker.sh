#!/bin/sh
cp -r /src /build
cd /build/src

scripts/makebuild.py
poetry install
ninja -v lint
ninja -v protos
poetry build

mv /build/src/dist /src
