#! /bin/bash

export ARCH=arm64
export CROSS_COMPILE=/home/lgj/work/toolchain/bin/aarch64-linux-gnu-
make defconfig
make
