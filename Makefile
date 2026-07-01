export TARGET = iphone:clang:latest:16.0
export ARCHS = arm64

INSTALL_TARGET_PROCESSES = 鹅鸭杀

TWEAK_NAME = KakaHookEngine

KakaHookEngine_FILES = Source/KakaHookEngine.m fishhook/fishhook.c
KakaHookEngine_FRAMEWORKS = UIKit Foundation Security
KakaHookEngine_CFLAGS = -fobjc-arc -Wno-deprecated-declarations

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
