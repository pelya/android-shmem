#!/bin/sh

[ -e libancillary/ancillary.h ] || git submodule update --init libancillary || exit 1

arm-linux-gnueabi-gcc -march=armv5 -shared -fpic -std=gnu99 *.c -I . -I libancillary \
	-o libandroid-shmem-gnueabi.so -Wl,--version-script=exports.txt -lc -lpthread && \
arm-linux-gnueabi-strip libandroid-shmem-gnueabi.so

arm-linux-gnueabihf-gcc -march=armv7-a -shared -fpic -std=gnu99 *.c -I . -I libancillary \
	-o libandroid-shmem-gnueabihf.so -Wl,--version-script=exports.txt -lc -lpthread && \
arm-linux-gnueabihf-strip libandroid-shmem-gnueabihf.so

