LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := android-shmem

LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS := -O3 -I$(LOCAL_PATH)/libancillary -D_LINUX_IPC_H

LOCAL_CPP_EXTENSION := .cpp

LOCAL_SRC_FILES := $(notdir $(wildcard $(LOCAL_PATH)/*.c))

LOCAL_SHARED_LIBRARIES :=

LOCAL_STATIC_LIBRARIES :=

LOCAL_LDFLAGS := -Wl,--version-script=$(LOCAL_PATH)/exports.txt

LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog

include $(BUILD_SHARED_LIBRARY)
