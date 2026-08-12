#!/usr/bin/env python3
"""Make SwiftUtils a direct package dependency of idownloadd.

Xcode 26 can fail to expose iDownload's transitive SwiftUtils module while
cross-building this command-line target for iphoneos on a headless runner.
Adding the package/product directly to the target keeps SwiftPM's dependency
plan explicit. The patch is idempotent and only touches known project anchors.
"""

from pathlib import Path

PROJECT = Path(__file__).resolve().parent / "src/idownloadd.xcodeproj/project.pbxproj"
text = PROJECT.read_text()

PACKAGE_ID = "A18B30000000000000000001"
PRODUCT_ID = "A18B30000000000000000002"
BUILD_FILE_ID = "A18B30000000000000000003"

if PACKAGE_ID in text and PRODUCT_ID in text and BUILD_FILE_ID in text:
    print("SwiftUtils direct dependency already present")
    raise SystemExit(0)

replacements = [
    (
        "\t\t8C69A22E2A320CCC007E401C /* iDownload in Frameworks */ = {isa = PBXBuildFile; productRef = 8C69A22D2A320CCC007E401C /* iDownload */; };\n",
        "\t\t8C69A22E2A320CCC007E401C /* iDownload in Frameworks */ = {isa = PBXBuildFile; productRef = 8C69A22D2A320CCC007E401C /* iDownload */; };\n"
        f"\t\t{BUILD_FILE_ID} /* SwiftUtils in Frameworks */ = {{isa = PBXBuildFile; productRef = {PRODUCT_ID} /* SwiftUtils */; }};\n",
    ),
    (
        "\t\t\t\t8C69A22E2A320CCC007E401C /* iDownload in Frameworks */,\n",
        "\t\t\t\t8C69A22E2A320CCC007E401C /* iDownload in Frameworks */,\n"
        f"\t\t\t\t{BUILD_FILE_ID} /* SwiftUtils in Frameworks */,\n",
    ),
    (
        "\t\t\tpackageProductDependencies = (\n\t\t\t\t8C69A22D2A320CCC007E401C /* iDownload */,\n\t\t\t);\n",
        "\t\t\tpackageProductDependencies = (\n"
        "\t\t\t\t8C69A22D2A320CCC007E401C /* iDownload */,\n"
        f"\t\t\t\t{PRODUCT_ID} /* SwiftUtils */,\n"
        "\t\t\t);\n",
    ),
    (
        "\t\t\tpackageReferences = (\n\t\t\t\t8C69A22C2A320CCC007E401C /* XCRemoteSwiftPackageReference \"iDownload\" */,\n\t\t\t);\n",
        "\t\t\tpackageReferences = (\n"
        "\t\t\t\t8C69A22C2A320CCC007E401C /* XCRemoteSwiftPackageReference \"iDownload\" */,\n"
        f"\t\t\t\t{PACKAGE_ID} /* XCRemoteSwiftPackageReference \"SwiftUtils\" */,\n"
        "\t\t\t);\n",
    ),
    (
        "\t\t8C69A22C2A320CCC007E401C /* XCRemoteSwiftPackageReference \"iDownload\" */ = {\n"
        "\t\t\tisa = XCRemoteSwiftPackageReference;\n"
        "\t\t\trepositoryURL = \"https://github.com/pinauten/iDownload\";\n"
        "\t\t\trequirement = {\n"
        "\t\t\t\tbranch = master;\n"
        "\t\t\t\tkind = branch;\n"
        "\t\t\t};\n"
        "\t\t};\n",
        "\t\t8C69A22C2A320CCC007E401C /* XCRemoteSwiftPackageReference \"iDownload\" */ = {\n"
        "\t\t\tisa = XCRemoteSwiftPackageReference;\n"
        "\t\t\trepositoryURL = \"https://github.com/pinauten/iDownload\";\n"
        "\t\t\trequirement = {\n"
        "\t\t\t\tbranch = master;\n"
        "\t\t\t\tkind = branch;\n"
        "\t\t\t};\n"
        "\t\t};\n"
        f"\t\t{PACKAGE_ID} /* XCRemoteSwiftPackageReference \"SwiftUtils\" */ = {{\n"
        "\t\t\tisa = XCRemoteSwiftPackageReference;\n"
        "\t\t\trepositoryURL = \"https://github.com/pinauten/SwiftUtils\";\n"
        "\t\t\trequirement = {\n"
        "\t\t\t\tbranch = master;\n"
        "\t\t\t\tkind = branch;\n"
        "\t\t\t};\n"
        "\t\t};\n",
    ),
    (
        "\t\t8C69A22D2A320CCC007E401C /* iDownload */ = {\n"
        "\t\t\tisa = XCSwiftPackageProductDependency;\n"
        "\t\t\tpackage = 8C69A22C2A320CCC007E401C /* XCRemoteSwiftPackageReference \"iDownload\" */;\n"
        "\t\t\tproductName = iDownload;\n"
        "\t\t};\n",
        "\t\t8C69A22D2A320CCC007E401C /* iDownload */ = {\n"
        "\t\t\tisa = XCSwiftPackageProductDependency;\n"
        "\t\t\tpackage = 8C69A22C2A320CCC007E401C /* XCRemoteSwiftPackageReference \"iDownload\" */;\n"
        "\t\t\tproductName = iDownload;\n"
        "\t\t};\n"
        f"\t\t{PRODUCT_ID} /* SwiftUtils */ = {{\n"
        "\t\t\tisa = XCSwiftPackageProductDependency;\n"
        f"\t\t\tpackage = {PACKAGE_ID} /* XCRemoteSwiftPackageReference \"SwiftUtils\" */;\n"
        "\t\t\tproductName = SwiftUtils;\n"
        "\t\t};\n",
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one project anchor, found {count}: {old.splitlines()[0]!r}")
    text = text.replace(old, new, 1)

PROJECT.write_text(text)
print("Added direct SwiftUtils package/product dependency to idownloadd")
