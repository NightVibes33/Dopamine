.PHONY: all clean build_clean

all: Dopamine.ipa

APP_PATH = build/Debug-iphoneos/Dopamine.app

Dopamine.ipa: $(APP_PATH)
	@echo Ad-Hoc signing Dopamine
	xattr -rc $(APP_PATH)
	ldid -SDopamine/Dopamine.entitlements $(APP_PATH)/Dopamine
	ldid -s $(APP_PATH)
	rm -rf Payload Dopamine.ipa
	mkdir Payload
	cp -r $(APP_PATH) Payload/Dopamine.app
	zip -Ar Dopamine.ipa Payload
	rm -rf Payload
	rm -rf Dopamine.tipa
	cp Dopamine.ipa Dopamine.tipa

XCODE_TARGET_FLAGS = -project Dopamine.xcodeproj -target Dopamine -configuration Debug
XCODE_DEVICE_FLAGS = -sdk iphoneos ARCHS=arm64 ONLY_ACTIVE_ARCH=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO

ifeq ($(NIGHTLY), 1)
$(APP_PATH): FORCE
	xcodebuild $(XCODE_TARGET_FLAGS) $(XCODE_DEVICE_FLAGS) GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"' build
else
$(APP_PATH): FORCE
	xcodebuild $(XCODE_TARGET_FLAGS) $(XCODE_DEVICE_FLAGS) build
endif

clean:
	rm -rf build Payload Dopamine.ipa Dopamine.tipa

build_clean:
	rm -rf Payload build

FORCE: ;