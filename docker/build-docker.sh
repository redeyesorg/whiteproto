#!/bin/sh
cp -r /src /build
cd /build/src

task clean build

cp -r /build/src/dist /src
