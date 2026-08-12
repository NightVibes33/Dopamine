XCODE_PROJECT = src/idownloadd.xcodeproj
XCODE_SCHEME = idownloadd
CS_FLAGS = CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
PLATFORM_FLAGS = -sdk iphoneos SDKROOT=iphoneos SUPPORTED_PLATFORMS=iphoneos SUPPORTS_MACCATALYST=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=NO
CONFIGURATION = Release
DERIVED_DATA = .derived
BUILD_OUTPUT = $(DERIVED_DATA)/Build/Products/Release-iphoneos

OUTPUT_NAME = idownloadd

build:
	@python3 patch_swiftutils_dependency.py
	@rm -rf "$(DERIVED_DATA)"
	xcodebuild -project $(XCODE_PROJECT) -scheme $(XCODE_SCHEME) -configuration $(CONFIGURATION) -derivedDataPath "$(DERIVED_DATA)" $(PLATFORM_FLAGS) $(CS_FLAGS) build
	@cp -f "$(BUILD_OUTPUT)/$(OUTPUT_NAME)" .
	@rm -rf "$(DERIVED_DATA)"
	@ldid -Cadhoc -Sentitlements.plist $(OUTPUT_NAME)

clean:
	xcodebuild -project $(XCODE_PROJECT) -scheme $(XCODE_SCHEME) -configuration $(CONFIGURATION) -derivedDataPath "$(DERIVED_DATA)" $(PLATFORM_FLAGS) clean
	@rm -rf "$(DERIVED_DATA)" $(OUTPUT_NAME)

default: build
