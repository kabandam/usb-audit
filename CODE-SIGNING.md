# Smart Console code signing

Smart Console supports Authenticode signing in the Windows release workflow.

## Required certificate

Use a CA-issued Windows code-signing certificate for CRECCOM. Do not generate a self-signed production certificate and do not place a private key in the repository.

Export the certificate and private key as a password-protected PFX file.

## GitHub Actions secrets

Configure these repository Actions secrets:

- `SMARTCONSOLE_CODESIGN_PFX_BASE64` — base64 representation of the password-protected PFX.
- `SMARTCONSOLE_CODESIGN_PASSWORD` — password for the PFX.

The workflow signs only CRECCOM-owned Smart Console executables and assemblies, then signs `SmartConsoleSetup.exe`. Each signature is verified with `signtool verify /pa` before the release is published.

If neither secret is configured, the build remains SHA-256 verified but unsigned and the workflow emits a warning. If only one secret is configured, the build fails instead of publishing a partially configured release.

## Antivirus policy

Do not make the agent add itself to antivirus exclusions and do not disable antivirus protection. If Kaspersky still produces a false positive on a signed release, submit that exact signed release/hash to Kaspersky for false-positive review and, on CRECCOM-managed endpoints, use a narrowly scoped trusted-application rule for the signed CRECCOM publisher or exact signed binaries.
