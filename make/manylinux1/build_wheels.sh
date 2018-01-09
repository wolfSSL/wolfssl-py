#!/bin/bash
set -e
set -x

docker run \
    --rm \
    -v `pwd`:/wolfssl-py \
    -w /wolfssl-py \
    wolfssl/manylinux1-x86_64 \
    bash -c "make/manylinux1/build.sh"
