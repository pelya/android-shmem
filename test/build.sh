#!/bin/sh

gcc -m32 -std=gnu99 *.c -o test-debian-x86

arm-linux-gnueabihf-gcc -march=armv7-a -std=gnu99 *.c -o test-debian-armhf

./setCrossEnvironment-armeabi-v7a.sh sh -c \
'set -x ; $CC $CFLAGS -I`pwd`/.. -D_LINUX_IPC_H $LDFLAGS *.c -o test-android'
