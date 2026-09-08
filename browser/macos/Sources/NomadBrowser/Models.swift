import CryptoKit
import Foundation

struct NomadDocument: Codable, Sendable, Hashable {
    let title: String
    let summary: String
    let body: String
    let tags: [String]
    let publishedAt: String
    let publisherName: String
    let mediaType: String
}

struct SignedEnvelope: Codable, Sendable {
    let version: Int
    let payload: String
    let contentHash: String
    let publisherKey: String
    let signature: String
    let identity: SiteIdentityBundle?

    init(
        version: Int,
        payload: String,
        contentHash: String,
        publisherKey: String,
        signature: String,
        identity: SiteIdentityBundle? = nil
    ) {
        self.version = version
        self.payload = payload
        self.contentHash = contentHash
        self.publisherKey = publisherKey
        self.signature = signature
        self.identity = identity
    }
}

enum PublisherIdentityState: String, Codable, Sendable, Hashable {
    case verified
    case unanchored
    case unknown
    case invalid
}

struct VerifiedDocument: Identifiable, Sendable, Hashable {
    let id: String
    let document: NomadDocument
    let publisherFingerprint: String
    let publisherIdentity: PublisherIdentityState
    let siteID: String?

    var trustedPublisher: Bool { publisherIdentity == .verified }
}

enum ObjectVerificationError: LocalizedError, Equatable {
    case unsupportedVersion
    case malformedEncoding
    case objectTooLarge
    case commitmentMismatch
    case invalidSignature
    case unsupportedMediaType
    case invalidDocument

    var errorDescription: String? {
        switch self {
        case .unsupportedVersion: return "Objektversionen stöds inte."
        case .malformedEncoding: return "Objektets kodning är ogiltig."
        case .objectTooLarge: return "Objektet överskrider säkerhetsgränsen."
        case .commitmentMismatch: return "Objektets SHA-256-åtagande stämmer inte."
        case .invalidSignature: return "Objektets Ed25519-signatur är ogiltig."
        case .unsupportedMediaType: return "Objektets medietyp stöds inte av den säkra renderaren."
        case .invalidDocument: return "Dokumentets innehåll är ogiltigt."
        }
    }
}

enum ObjectVerifier {
    static let maximumPayloadBytes = 262_144
    static let maximumBodyCharacters = 200_000
    static let maximumTitleCharacters = 300
    static let maximumSummaryCharacters = 2_000
    static let maximumPublisherNameCharacters = 200
    static let maximumPublishedAtCharacters = 64
    static let maximumTags = 64
    static let objectDomain = Data("nomad-object-v1".utf8)

    // Object verification establishes integrity only. Publisher identity is a
    // separate SiteID claim and must never be inferred from an embedded key or
    // a build-time allowlist. A self-consistent SiteID bundle is still not a
    // current identity anchor: without monotonic local state, an attacker could
    // replay an older valid chain. Such evidence is therefore UNANCHORED until
    // the materializer supplies a persisted, rollback-resistant accepted head.
    static func verify(_ envelope: SignedEnvelope) throws -> VerifiedDocument {
        guard envelope.version == 1 else {
            throw ObjectVerificationError.unsupportedVersion
        }
        guard
            let payload = Data(base64Encoded: envelope.payload),
            payload.base64EncodedString() == envelope.payload,
            let publisherKey = Data(base64Encoded: envelope.publisherKey),
            publisherKey.base64EncodedString() == envelope.publisherKey,
            let signature = Data(base64Encoded: envelope.signature),
            signature.base64EncodedString() == envelope.signature,
            payload.count <= maximumPayloadBytes,
            publisherKey.count == 32,
            signature.count == 64
        else {
            throw ObjectVerificationError.malformedEncoding
        }

        let digest = Data(SHA256.hash(data: payload))
        guard digest.hexString == envelope.contentHash, envelope.contentHash == envelope.contentHash.lowercased() else {
            throw ObjectVerificationError.commitmentMismatch
        }
        var signingMessage = objectDomain
        signingMessage.append(digest)
        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: publisherKey)
        } catch {
            throw ObjectVerificationError.malformedEncoding
        }
        guard key.isValidSignature(signature, for: signingMessage) else {
            throw ObjectVerificationError.invalidSignature
        }

        do {
            try StrictJSON.validateDocumentPayload(payload)
        } catch {
            throw ObjectVerificationError.invalidDocument
        }
        let document: NomadDocument
        do {
            document = try JSONDecoder().decode(NomadDocument.self, from: payload)
        } catch {
            throw ObjectVerificationError.invalidDocument
        }
        guard document.mediaType == "text/plain; charset=utf-8" else {
            throw ObjectVerificationError.unsupportedMediaType
        }
        guard
            !document.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
            document.title.count <= maximumTitleCharacters,
            document.summary.count <= maximumSummaryCharacters,
            document.body.count <= maximumBodyCharacters,
            document.publisherName.count <= maximumPublisherNameCharacters,
            document.publishedAt.count <= maximumPublishedAtCharacters,
            document.tags.count <= maximumTags,
            document.tags.allSatisfy({ $0.count <= 100 })
        else {
            throw ObjectVerificationError.invalidDocument
        }

        var identityState = PublisherIdentityState.unknown
        var siteID: String?
        if let identity = envelope.identity {
            do {
                siteID = try SiteIdentityVerifier.resolve(
                    bundle: identity,
                    object: payload,
                    objectPublisherKey: publisherKey,
                    objectSignature: signature
                )
                identityState = .unanchored
            } catch {
                identityState = .invalid
                siteID = nil
            }
        }

        return VerifiedDocument(
            id: digest.hexString,
            document: document,
            publisherFingerprint: String(Data(SHA256.hash(data: publisherKey)).hexString.prefix(16)),
            publisherIdentity: identityState,
            siteID: siteID
        )
    }
}

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
