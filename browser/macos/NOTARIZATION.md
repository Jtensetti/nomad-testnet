# Apple release credential handoff

The notarized release workflow reads credentials only from the protected
GitHub environment `apple-release`. Never commit, paste into an issue, or print
any credential in a workflow log.

Configure these environment secrets:

| Secret | Value |
|---|---|
| `APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64` | Base64 of an exported Developer ID Application certificate and private key in PKCS#12 format. |
| `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD` | Password used for the PKCS#12 archive. |
| `APPLE_NOTARY_KEY_P8_BASE64` | Base64 of the App Store Connect API private key (`.p8`). |
| `APPLE_NOTARY_KEY_ID` | App Store Connect API key ID. |
| `APPLE_NOTARY_ISSUER_ID` | App Store Connect issuer ID. |
| `APPLE_TEAM_ID` | Ten-character Apple Developer team ID expected in the signed app. |

Protect the environment with required reviewers, restrict deployment branches
to `agent/macos-browser` until merge, and give the App Store Connect key only
the minimum access needed for notarization. Rotate credentials immediately if
GitHub reports a secret-scanning alert or a workflow prints sensitive material.

Run **macOS notarized release** manually with an unused semantic version. The
workflow fails closed when a secret is absent, the certificate is not a valid
Developer ID Application identity, the team does not match, a secure timestamp
is absent, Apple does not return `Accepted`, stapling fails, Gatekeeper rejects
the disk image/application, or the app gains network entitlements/frameworks.

The release contains the notarized DMG, a checksum, Apple's submission result
and Apple's notarization log. GitHub environment secrets are not included in
those artifacts.
