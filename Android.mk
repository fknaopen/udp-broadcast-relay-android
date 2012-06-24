LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES:= udp_bcast_relay.cpp
LOCAL_MODULE := udp_bcast_relay
LOCAL_STATIC_LIBRARIES := libcutils libc
#LOCAL_SHARED_LIBRARIES := libcutils libc
include $(BUILD_EXECUTABLE)
