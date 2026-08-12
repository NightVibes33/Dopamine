XCODE_PROJECT = src/idownloadd.xcodeproj
XCODE_TARGET = idownloadd
CS_FLAGS = CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
PLATFORM_FLAGS = -sdk iphoneos SDKROOT=iphoneos SUPPORTED_PLATFORMS=iphoneos SUPPORTS_MACCATALYST=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=NO
CONFIGURATION = Release
BUILD_ROOT = src/build
BUILD_OUTPUT = $(BUILD_ROOT)/Release-iphoneos

OUTPUT_NAME = idownloadd

build:
	xcodebuild -project $(XCODE_PROJECT) -target $(XCODE_TARGET) -configuration $(CONFIGURATION) $(PLATFORM_FLAGS) $(CS_FLAGS) build
	@cp -f "$(BUILD_OUTPUT)/$(OUTPUT_NAME)" .
	@rm -rf "$(BUILD_ROOT)"
	@ldid -Cadhoc -Sentitlements.plist $(OUTPUT_NAME)

clean:
	xcodebuild -project $(XCODE_PROJECT) -target $(XCODE_TARGET) -configuration $(CONFIGURATION) $(PLATFORM_FLAGS) clean
	@rm -rf "$(BUILD_ROOT)" $(OUTPUT_NAME)

default: build
