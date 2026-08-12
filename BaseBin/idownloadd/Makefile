XCODE_PROJECT = src/idownloadd.xcodeproj
XCODE_SCHEME = idownloadd
CS_FLAGS = CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
PLATFORM_FLAGS = -sdk iphoneos SDKROOT=iphoneos SUPPORTED_PLATFORMS=iphoneos SUPPORTS_MACCATALYST=NO
CONFIGURATION = Release

OUTPUT_NAME = idownloadd

build:
	xcodebuild -archivePath ./.build -project $(XCODE_PROJECT) -scheme $(XCODE_SCHEME) -configuration $(CONFIGURATION) -destination generic/platform=iOS archive $(PLATFORM_FLAGS) $(CS_FLAGS)
	@cp -f ./.build.xcarchive/Products/usr/local/bin/$(OUTPUT_NAME) .
	@rm -rf ./.build.xcarchive
	@ldid -Cadhoc -Sentitlements.plist $(OUTPUT_NAME)

clean:
	xcodebuild -project $(XCODE_PROJECT) -scheme $(XCODE_SCHEME) -configuration $(CONFIGURATION) -destination generic/platform=iOS clean $(PLATFORM_FLAGS)
	@rm -rf $(OUTPUT_NAME)

default: build