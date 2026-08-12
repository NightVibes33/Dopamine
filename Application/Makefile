.PHONY: all clean build_clean

all: Dopamine.ipa

Dopamine.ipa: build/Build/Products/Debug-iphoneos/Dopamine.app
	@echo Ad-Hoc signing Dopamine
	xattr -rc build/Build/Products/Debug-iphoneos/Dopamine.app
	ldid -SDopamine/Dopamine.entitlements build/Build/Products/Debug-iphoneos/Dopamine.app/Dopamine
	ldid -s build/Build/Products/Debug-iphoneos/Dopamine.app
	rm -rf Payload Dopamine.ipa
	mkdir Payload
	cp -r build/Build/Products/Debug-iphoneos/Dopamine.app Payload/Dopamine.app
	zip -Ar Dopamine.ipa Payload
	rm -rf Payload
	rm -rf Dopamine.tipa
	cp Dopamine.ipa Dopamine.tipa

XCODE_DEVICE_FLAGS = -sdk iphoneos SDKROOT=iphoneos SUPPORTED_PLATFORMS=iphoneos SUPPORTS_MACCATALYST=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
XCODE_TARGET_FLAGS = -project Dopamine.xcodeproj -target Dopamine -configuration Debug SYMROOT="$(CURDIR)/build/Build/Products" OBJROOT="$(CURDIR)/build/Build/Intermediates.noindex"

ifeq ($(NIGHTLY), 1)
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild $(XCODE_TARGET_FLAGS) $(XCODE_DEVICE_FLAGS) GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"' build
else
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild $(XCODE_TARGET_FLAGS) $(XCODE_DEVICE_FLAGS) build
endif

clean:
	rm -rf build Payload Dopamine.ipa Dopamine.tipa

build_clean:
	rm -rf Payload build

FORCE: ;