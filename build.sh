#!/bin/sh

[ -e libancillary/ancillary.h ] || git submodule update --init libancillary || exit 1

gcc -shared -fPIC -std=gnu99 -Wall *.c -I . -I libancillary \
	-o libandroid-shmem-`arch`.so -Wl,--version-script=exports.txt -lc -lpthread && \
	strip libandroid-shmem-`arch`.so
