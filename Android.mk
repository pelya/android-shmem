LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := android-shmem

LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS := -O3 -I$(LOCAL_PATH)/libancillary

LOCAL_CPP_EXTENSION := .cpp

LOCAL_SRC_FILES := $(notdir $(wildcard $(LOCAL_PATH)/*.c))

LOCAL_SHARED_LIBRARIES := -llog

LOCAL_STATIC_LIBRARIES := 

LOCAL_LDFLAGS := -Wl,--version-script=$(LOCAL_PATH)/exports.txt

include $(BUILD_SHARED_LIBRARY)
