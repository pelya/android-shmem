
ARCH:=$(shell arch)
SRCS:=$(wildcard *.c)


all: libandroid-shmem-$(ARCH).so

libandroid-shmem-$(ARCH).so: libancillary/ancillary.h $(SRCS)
	$(CC) -shared -fpic -std=gnu99 -Wall $(SRCS) -I . -I libancillary $(CFLAGS) \
		-o $@ -Wl,--version-script=exports.txt -lc -lpthread $(LDFLAGS)
	strip $@

libancillary/ancillary.h:
	git submodule update --init libancillary
