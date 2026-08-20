# Automated analysis pipeline

The `A15 Legacy Restore Analysis` workflow performs the following reproducible sequence on `research/a15-legacy-restore-lab`:

1. Run the offline unit test suite.
2. Load the verified `iPhone14,6` hardware/firmware target profile.
3. Use HTTP byte ranges against the exact Apple CDN IPSW to extract only `BuildManifest.plist`.
4. Verify the D49AP / CPID 0x8110 / BDID 0x10 BuildIdentity.
5. Generate the structured manifest report.
6. Generate the component matrix.
7. Upload the manifest and reports as the `iPhone14-6-19E241-manifest-analysis` workflow artifact.

The range reader explicitly aborts if the server ignores the Range request, preventing an accidental 5.6 GiB full-IPSW download.
