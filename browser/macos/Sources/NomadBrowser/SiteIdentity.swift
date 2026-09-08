import CryptoKit
import Foundation

struct SiteRecoveryPolicy: Codable, Sendable, Hashable {
    let threshold: UInt32
    let keys: [String]
}

struct SiteAuthorization: Codable, Sendable, Hashable {
    let role: String
    let key: String
    let signature: String
}

struct SiteDescriptor: Codable, Sendable, Hashable {
    let version: String
    let siteID: String
    let sequence: UInt64
    let transition: String
    let previousDescriptorDigest: String
    let validFrom: String
    let validUntil: String
    let signingKeys: [String]
    let revokedKeys: [String]
    let recovery: SiteRecoveryPolicy
    let authorizations: [SiteAuthorization]

    enum CodingKeys: String, CodingKey {
        case version
        case siteID = "site_id"
        case sequence
        case transition
        case previousDescriptorDigest = "previous_descriptor_digest"
        case validFrom = "valid_from"
        case validUntil = "valid_until"
        case signingKeys = "signing_keys"
        case revokedKeys = "revoked_keys"
        case recovery
        case authorizations
    }
}

struct SitePublication: Codable, Sendable, Hashable {
    let version: String
    let siteID: String
    let descriptorDigest: String
    let signingKey: String
    let objectRoot: String
    let manifestDigest: String
    let publishedAt: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case version
        case siteID = "site_id"
        case descriptorDigest = "descriptor_digest"
        case signingKey = "signing_key"
        case objectRoot = "object_root"
        case manifestDigest = "manifest_digest"
        case publishedAt = "published_at"
        case signature
    }
}

// Identity evidence travels with a locally materialized object. The browser
// never fetches it in response to a query. A complete bundle is required for
// PublisherIdentityState.verified; absence is UNKNOWN and malformed or
// contradictory evidence is INVALID without changing the already-established
// object-integrity result.
struct SiteIdentityBundle: Codable, Sendable, Hashable {
    let descriptors: [SiteDescriptor]
    let publication: SitePublication
    let manifest: String // canonical base64 of the exact 228-byte manifest
}

enum SiteIdentityError: Error, Equatable {
    case malformed(String)
    case invalid(String)
}

struct VerifiedSiteDescriptor: Sendable, Hashable {
    let descriptor: SiteDescriptor
    let digest: Data
    let siteID: Data
    let validFrom: Date
    let validUntil: Date

    func active(at date: Date) -> Bool {
        date >= validFrom && date < validUntil
    }

    func authorizes(_ key: Data) -> Bool {
        guard
            let active = try? SiteIdentityVerifier.decodeKeyList(descriptor.signingKeys, limit: SiteIdentityVerifier.maxKeys),
            let revoked = try? SiteIdentityVerifier.decodeKeyList(descriptor.revokedKeys, limit: SiteIdentityVerifier.maxRevokedKeys)
        else { return false }
        return active.contains(key) && !revoked.contains(key)
    }
}

struct ParsedNomadManifest: Sendable, Hashable {
    let wire: Data
    let length: UInt64
    let basin: UInt64
    let generation: Data
    let root: Data
    let publicKey: Data
    let objectSignature: Data
    let manifestSignature: Data
}

enum SiteIdentityVerifier {
    static let descriptorVersion = "nomad-site-descriptor-v1"
    static let publicationVersion = "nomad-site-publication-v1"
    static let siteIDDomain = Data("nomad-siteid-v1".utf8)
    static let descriptorDigestDomain = Data("nomad-site-descriptor-digest-v1".utf8)
    static let authorizationDomain = Data("nomad-site-authorization-v1".utf8)
    static let publicationDomain = Data("nomad-site-publication-v1".utf8)
    static let objectDomain = Data("nomad-object-v1".utf8)
    static let manifestDomain = Data("nomad-manifest-v1".utf8)
    static let generationDomain = Data("nomad-generation-v1".utf8)

    static let maxKeys = 8
    static let maxRevokedKeys = 1_024
    static let maxAuthorizations = 4 * maxKeys
    static let maxDescriptors = 1_024
    static let manifestSize = 228

    private static let transitionGenesis = "genesis"
    private static let transitionRotation = "rotation"
    private static let transitionRecovery = "recovery"
    private static let transitionRevocation = "revocation"
    private static let roleSigning: UInt8 = 0x01
    private static let roleRecovery: UInt8 = 0x02

    static func resolve(
        bundle: SiteIdentityBundle,
        object: Data,
        objectPublisherKey: Data,
        objectSignature: Data
    ) throws -> String {
        let chain = try verifyChain(bundle.descriptors)
        guard let head = chain.last else {
            throw SiteIdentityError.invalid("descriptor chain is empty")
        }

        let manifestWire = try decodeCanonicalBase64(bundle.manifest, size: manifestSize)
        let manifest = try parseManifest(manifestWire)
        try verifyManifestObject(manifest, object: object)

        guard manifest.publicKey == objectPublisherKey, manifest.objectSignature == objectSignature else {
            throw SiteIdentityError.invalid("materialized envelope differs from the identity-bound manifest")
        }

        let publication = bundle.publication
        let publicationCanonical = try publicationCanonicalBytes(publication)
        guard publication.siteID == head.descriptor.siteID else {
            throw SiteIdentityError.invalid("publication claims a different SiteID")
        }
        guard try decodeCanonicalHex(publication.objectRoot, size: 32) == manifest.root else {
            throw SiteIdentityError.invalid("publication is for a different object")
        }
        let expectedManifestDigest = Data(SHA256.hash(data: manifest.wire))
        guard try decodeCanonicalHex(publication.manifestDigest, size: 32) == expectedManifestDigest else {
            throw SiteIdentityError.invalid("publication is for a different manifest")
        }

        let signingKey = try decodeCanonicalBase64(publication.signingKey, size: 32)
        let signature = try decodeCanonicalBase64(publication.signature, size: 64)
        var publicationMessage = publicationDomain
        publicationMessage.append(publicationCanonical)
        guard verifyEd25519(signature: signature, message: publicationMessage, key: signingKey) else {
            throw SiteIdentityError.invalid("publication signature verification failed")
        }

        let descriptorDigest = try decodeCanonicalHex(publication.descriptorDigest, size: 32)
        guard let authorizing = chain.first(where: { $0.digest == descriptorDigest }) else {
            throw SiteIdentityError.invalid("publication names a descriptor outside the accepted chain")
        }
        let publishedAt = try canonicalDate(publication.publishedAt)
        guard authorizing.active(at: publishedAt) else {
            throw SiteIdentityError.invalid("authorizing descriptor was not active at publication time")
        }
        guard authorizing.authorizes(signingKey) else {
            throw SiteIdentityError.invalid("publication key is not active in the authorizing descriptor")
        }
        let headRevoked = try decodeKeyList(head.descriptor.revokedKeys, limit: maxRevokedKeys)
        guard !headRevoked.contains(signingKey) else {
            throw SiteIdentityError.invalid("publication key has been revoked")
        }

        return head.descriptor.siteID
    }

    static func verifyChain(_ descriptors: [SiteDescriptor]) throws -> [VerifiedSiteDescriptor] {
        guard !descriptors.isEmpty, descriptors.count <= maxDescriptors else {
            throw SiteIdentityError.invalid("descriptor chain is empty or too long")
        }
        var verified: [VerifiedSiteDescriptor] = []
        verified.reserveCapacity(descriptors.count)
        for descriptor in descriptors {
            let previous = verified.last
            verified.append(try verifyDescriptor(descriptor, previous: previous))
        }
        return verified
    }

    static func verifyDescriptor(_ descriptor: SiteDescriptor, previous: VerifiedSiteDescriptor?) throws -> VerifiedSiteDescriptor {
        try validateStructure(descriptor)
        let digest = try descriptorDigest(descriptor)
        let validFrom = try canonicalDate(descriptor.validFrom)
        let validUntil = try canonicalDate(descriptor.validUntil)
        guard validFrom < validUntil else {
            throw SiteIdentityError.invalid("descriptor validity window is empty")
        }
        let siteID = try decodeCanonicalHex(descriptor.siteID, size: 32)

        if descriptor.transition == transitionGenesis {
            guard previous == nil else {
                throw SiteIdentityError.invalid("genesis cannot follow an existing descriptor")
            }
            let derived = try deriveSiteID(descriptor)
            guard derived == siteID else {
                throw SiteIdentityError.invalid("genesis does not commit to its own SiteID")
            }
            guard descriptor.revokedKeys.isEmpty else {
                throw SiteIdentityError.invalid("genesis cannot revoke keys")
            }
        } else {
            guard let previous else {
                throw SiteIdentityError.invalid("non-genesis descriptor requires a predecessor")
            }
            guard siteID == previous.siteID else {
                throw SiteIdentityError.invalid("descriptor belongs to another SiteID")
            }
            guard descriptor.sequence == previous.descriptor.sequence + 1 else {
                throw SiteIdentityError.invalid("descriptor sequence is not contiguous")
            }
            guard try decodeCanonicalHex(descriptor.previousDescriptorDigest, size: 32) == previous.digest else {
                throw SiteIdentityError.invalid("descriptor chain digest mismatch")
            }
            try checkRevocationAbsorption(descriptor, previous: previous)
            if descriptor.transition == transitionRecovery {
                try requireRecoveryRevokesPriorSigning(descriptor, previous: previous)
            }
            try checkRecoveryPolicyAuthority(descriptor, previous: previous, digest: digest)
        }

        let verifiedAuthorizations = try verifyAuthorizations(descriptor, digest: digest, previous: previous)
        try requirePossessionOfNewKeys(descriptor, digest: digest, previous: previous, verified: verifiedAuthorizations)

        return VerifiedSiteDescriptor(
            descriptor: descriptor,
            digest: digest,
            siteID: siteID,
            validFrom: validFrom,
            validUntil: validUntil
        )
    }

    static func deriveSiteID(_ descriptor: SiteDescriptor) throws -> Data {
        guard descriptor.transition == transitionGenesis, descriptor.sequence == 0 else {
            throw SiteIdentityError.invalid("SiteID derives only from sequence-zero genesis")
        }
        guard descriptor.previousDescriptorDigest == String(repeating: "0", count: 64) else {
            throw SiteIdentityError.invalid("genesis previous digest is not zero")
        }
        try validateStructure(descriptor)
        let core = try descriptorCanonicalBytes(descriptor, zeroSiteID: true)
        var input = siteIDDomain
        input.append(core)
        return Data(SHA256.hash(data: input))
    }

    static func descriptorDigest(_ descriptor: SiteDescriptor) throws -> Data {
        let canonical = try descriptorCanonicalBytes(descriptor, zeroSiteID: false)
        var input = descriptorDigestDomain
        input.append(canonical)
        return Data(SHA256.hash(data: input))
    }

    static func descriptorCanonicalBytes(_ descriptor: SiteDescriptor, zeroSiteID: Bool = false) throws -> Data {
        guard descriptor.version == descriptorVersion else {
            throw SiteIdentityError.invalid("unsupported descriptor version")
        }
        guard [transitionGenesis, transitionRotation, transitionRecovery, transitionRevocation].contains(descriptor.transition) else {
            throw SiteIdentityError.invalid("unsupported descriptor transition")
        }

        let siteID = zeroSiteID ? Data(repeating: 0, count: 32) : try decodeCanonicalHex(descriptor.siteID, size: 32)
        let previous = try decodeCanonicalHex(descriptor.previousDescriptorDigest, size: 32)
        _ = try canonicalDate(descriptor.validFrom)
        _ = try canonicalDate(descriptor.validUntil)
        let signing = try decodeKeyList(descriptor.signingKeys, limit: maxKeys)
        let revoked = try decodeKeyList(descriptor.revokedKeys, limit: maxRevokedKeys)
        let recovery = try decodeKeyList(descriptor.recovery.keys, limit: maxKeys)

        var out = Data()
        appendString(descriptor.version, to: &out)
        out.append(siteID)
        appendUInt64(descriptor.sequence, to: &out)
        appendString(descriptor.transition, to: &out)
        out.append(previous)
        appendString(descriptor.validFrom, to: &out)
        appendString(descriptor.validUntil, to: &out)
        appendKeyList(signing, to: &out)
        appendKeyList(revoked, to: &out)
        appendUInt32(descriptor.recovery.threshold, to: &out)
        appendKeyList(recovery, to: &out)
        guard out.count <= 1 << 20 else {
            throw SiteIdentityError.invalid("canonical descriptor exceeds size bound")
        }
        return out
    }

    static func publicationCanonicalBytes(_ publication: SitePublication) throws -> Data {
        guard publication.version == publicationVersion else {
            throw SiteIdentityError.invalid("unsupported publication version")
        }
        let siteID = try decodeCanonicalHex(publication.siteID, size: 32)
        let descriptorDigest = try decodeCanonicalHex(publication.descriptorDigest, size: 32)
        let signingKey = try decodeCanonicalBase64(publication.signingKey, size: 32)
        let objectRoot = try decodeCanonicalHex(publication.objectRoot, size: 32)
        let manifestDigest = try decodeCanonicalHex(publication.manifestDigest, size: 32)
        _ = try canonicalDate(publication.publishedAt)

        var out = Data()
        appendString(publication.version, to: &out)
        out.append(siteID)
        out.append(descriptorDigest)
        appendBytes(signingKey, to: &out)
        out.append(objectRoot)
        out.append(manifestDigest)
        appendString(publication.publishedAt, to: &out)
        return out
    }

    static func parseManifest(_ wire: Data) throws -> ParsedNomadManifest {
        guard wire.count == manifestSize else {
            throw SiteIdentityError.invalid("manifest length is not 228 bytes")
        }
        let magic = Data([0x4e, 0x4f, 0x4d, 0x01])
        guard wire.prefix(4) == magic else {
            throw SiteIdentityError.invalid("unsupported manifest magic")
        }
        let length = readUInt64(wire, offset: 4)
        let basin = readUInt64(wire, offset: 12)
        let generation = Data(wire[20..<36])
        let root = Data(wire[36..<68])
        let publicKey = Data(wire[68..<100])
        let objectSignature = Data(wire[100..<164])
        let manifestSignature = Data(wire[164..<228])
        guard length > 0 else {
            throw SiteIdentityError.invalid("manifest contains zero object length")
        }

        var generationInput = generationDomain
        generationInput.append(root)
        let expectedGeneration = Data(SHA256.hash(data: generationInput).prefix(16))
        guard generation == expectedGeneration else {
            throw SiteIdentityError.invalid("manifest generation does not match root")
        }

        var objectMessage = objectDomain
        objectMessage.append(root)
        guard verifyEd25519(signature: objectSignature, message: objectMessage, key: publicKey) else {
            throw SiteIdentityError.invalid("manifest object signature is invalid")
        }

        var manifestMessage = manifestDomain
        appendUInt64(length, to: &manifestMessage)
        appendUInt64(basin, to: &manifestMessage)
        manifestMessage.append(generation)
        manifestMessage.append(root)
        manifestMessage.append(publicKey)
        manifestMessage.append(objectSignature)
        guard verifyEd25519(signature: manifestSignature, message: manifestMessage, key: publicKey) else {
            throw SiteIdentityError.invalid("manifest signature is invalid")
        }

        return ParsedNomadManifest(
            wire: wire,
            length: length,
            basin: basin,
            generation: generation,
            root: root,
            publicKey: publicKey,
            objectSignature: objectSignature,
            manifestSignature: manifestSignature
        )
    }

    private static func verifyManifestObject(_ manifest: ParsedNomadManifest, object: Data) throws {
        guard UInt64(object.count) == manifest.length else {
            throw SiteIdentityError.invalid("object length differs from manifest")
        }
        guard Data(SHA256.hash(data: object)) == manifest.root else {
            throw SiteIdentityError.invalid("object root differs from manifest")
        }
    }

    private static func validateStructure(_ descriptor: SiteDescriptor) throws {
        let signing = try decodeKeyList(descriptor.signingKeys, limit: maxKeys)
        let revoked = try decodeKeyList(descriptor.revokedKeys, limit: maxRevokedKeys)
        let recovery = try decodeKeyList(descriptor.recovery.keys, limit: maxKeys)
        guard !signing.isEmpty else { throw SiteIdentityError.invalid("descriptor has no signing key") }
        guard !recovery.isEmpty else { throw SiteIdentityError.invalid("descriptor has no recovery key") }
        guard descriptor.recovery.threshold >= 1, Int(descriptor.recovery.threshold) <= recovery.count else {
            throw SiteIdentityError.invalid("invalid recovery threshold")
        }
        guard Set(signing).count == signing.count else { throw SiteIdentityError.invalid("duplicate signing key") }
        guard Set(revoked).count == revoked.count else { throw SiteIdentityError.invalid("duplicate revoked key") }
        guard Set(recovery).count == recovery.count else { throw SiteIdentityError.invalid("duplicate recovery key") }
        let revokedSet = Set(revoked)
        let signingSet = Set(signing)
        let recoverySet = Set(recovery)
        guard signingSet.isDisjoint(with: revokedSet) else { throw SiteIdentityError.invalid("active signing key is revoked") }
        guard signingSet.isDisjoint(with: recoverySet) else { throw SiteIdentityError.invalid("signing and recovery keys overlap") }
        guard recoverySet.isDisjoint(with: revokedSet) else { throw SiteIdentityError.invalid("active recovery key is revoked") }
    }

    private static func checkRevocationAbsorption(_ descriptor: SiteDescriptor, previous: VerifiedSiteDescriptor) throws {
        let oldRevoked = Set(try decodeKeyList(previous.descriptor.revokedKeys, limit: maxRevokedKeys))
        let newRevoked = Set(try decodeKeyList(descriptor.revokedKeys, limit: maxRevokedKeys))
        guard oldRevoked.isSubset(of: newRevoked) else {
            throw SiteIdentityError.invalid("descriptor drops a previous revocation")
        }
        let active = Set(try decodeKeyList(descriptor.signingKeys, limit: maxKeys) + decodeKeyList(descriptor.recovery.keys, limit: maxKeys))
        guard active.isDisjoint(with: oldRevoked) else {
            throw SiteIdentityError.invalid("descriptor reinstates a revoked key")
        }
    }

    private static func requireRecoveryRevokesPriorSigning(_ descriptor: SiteDescriptor, previous: VerifiedSiteDescriptor) throws {
        let oldSigning = Set(try decodeKeyList(previous.descriptor.signingKeys, limit: maxKeys))
        let revoked = Set(try decodeKeyList(descriptor.revokedKeys, limit: maxRevokedKeys))
        guard oldSigning.isSubset(of: revoked) else {
            throw SiteIdentityError.invalid("recovery does not revoke every previous signing key")
        }
    }

    private static func checkRecoveryPolicyAuthority(
        _ descriptor: SiteDescriptor,
        previous: VerifiedSiteDescriptor,
        digest: Data
    ) throws {
        let policyUnchanged = descriptor.recovery.threshold == previous.descriptor.recovery.threshold &&
            descriptor.recovery.keys == previous.descriptor.recovery.keys
        let newRevoked = Set(try decodeKeyList(descriptor.revokedKeys, limit: maxRevokedKeys))
        let oldRecovery = try decodeKeyList(previous.descriptor.recovery.keys, limit: maxKeys)
        let revokesRecovery = oldRecovery.contains(where: { newRevoked.contains($0) })
        if policyUnchanged && !revokesRecovery { return }

        let valid = try verifiedAuthorizationIDs(descriptor, digest: digest)
        var count = 0
        for key in oldRecovery {
            if valid.contains(authorizationID(role: "recovery", key: key)) { count += 1 }
        }
        guard count >= Int(previous.descriptor.recovery.threshold) else {
            throw SiteIdentityError.invalid("recovery policy change lacks previous recovery threshold")
        }
    }

    private static func verifyAuthorizations(
        _ descriptor: SiteDescriptor,
        digest: Data,
        previous: VerifiedSiteDescriptor?
    ) throws -> Set<String> {
        let verified = try verifiedAuthorizationIDs(descriptor, digest: digest)
        switch descriptor.transition {
        case transitionGenesis:
            for key in try decodeKeyList(descriptor.signingKeys, limit: maxKeys) {
                guard verified.contains(authorizationID(role: "signing", key: key)) else {
                    throw SiteIdentityError.invalid("genesis lacks a signing-key self-signature")
                }
            }
            for key in try decodeKeyList(descriptor.recovery.keys, limit: maxKeys) {
                guard verified.contains(authorizationID(role: "recovery", key: key)) else {
                    throw SiteIdentityError.invalid("genesis lacks a recovery-key self-signature")
                }
            }
        case transitionRotation:
            guard let previous else { throw SiteIdentityError.invalid("rotation has no predecessor") }
            try requireSigningMajority(verified, previous: previous)
        case transitionRecovery:
            guard let previous else { throw SiteIdentityError.invalid("recovery has no predecessor") }
            try requireRecoveryThreshold(verified, previous: previous)
        case transitionRevocation:
            guard let previous else { throw SiteIdentityError.invalid("revocation has no predecessor") }
            if (try? requireSigningMajority(verified, previous: previous)) == nil {
                try requireRecoveryThreshold(verified, previous: previous)
            }
        default:
            throw SiteIdentityError.invalid("unsupported descriptor transition")
        }
        return verified
    }

    private static func verifiedAuthorizationIDs(_ descriptor: SiteDescriptor, digest: Data) throws -> Set<String> {
        guard descriptor.authorizations.count <= maxAuthorizations else {
            throw SiteIdentityError.invalid("too many authorizations")
        }
        var verified = Set<String>()
        for authorization in descriptor.authorizations {
            let roleByte: UInt8
            switch authorization.role {
            case "signing": roleByte = roleSigning
            case "recovery": roleByte = roleRecovery
            default: throw SiteIdentityError.invalid("unsupported authorization role")
            }
            let key = try decodeCanonicalBase64(authorization.key, size: 32)
            let signature = try decodeCanonicalBase64(authorization.signature, size: 64)
            var message = authorizationDomain
            message.append(digest)
            message.append(roleByte)
            message.append(key)
            guard verifyEd25519(signature: signature, message: message, key: key) else {
                throw SiteIdentityError.invalid("authorization signature is invalid")
            }
            let id = authorizationID(role: authorization.role, key: key)
            guard verified.insert(id).inserted else {
                throw SiteIdentityError.invalid("duplicate authorization")
            }
        }
        return verified
    }

    private static func requirePossessionOfNewKeys(
        _ descriptor: SiteDescriptor,
        digest: Data,
        previous: VerifiedSiteDescriptor?,
        verified: Set<String>
    ) throws {
        guard let previous else { return }
        let oldKeys = Set(try decodeKeyList(previous.descriptor.signingKeys, limit: maxKeys) + decodeKeyList(previous.descriptor.recovery.keys, limit: maxKeys))
        for key in try decodeKeyList(descriptor.signingKeys, limit: maxKeys) where !oldKeys.contains(key) {
            guard verified.contains(authorizationID(role: "signing", key: key)) else {
                throw SiteIdentityError.invalid("new signing key does not prove possession")
            }
        }
        for key in try decodeKeyList(descriptor.recovery.keys, limit: maxKeys) where !oldKeys.contains(key) {
            guard verified.contains(authorizationID(role: "recovery", key: key)) else {
                throw SiteIdentityError.invalid("new recovery key does not prove possession")
            }
        }
        _ = digest // kept explicit: possession signatures are already checked against this digest above.
    }

    private static func requireSigningMajority(_ verified: Set<String>, previous: VerifiedSiteDescriptor) throws {
        let keys = try decodeKeyList(previous.descriptor.signingKeys, limit: maxKeys)
        let count = keys.filter { verified.contains(authorizationID(role: "signing", key: $0)) }.count
        let required = keys.count / 2 + 1
        guard count >= required else {
            throw SiteIdentityError.invalid("transition lacks previous signing-key majority")
        }
    }

    private static func requireRecoveryThreshold(_ verified: Set<String>, previous: VerifiedSiteDescriptor) throws {
        let keys = try decodeKeyList(previous.descriptor.recovery.keys, limit: maxKeys)
        let count = keys.filter { verified.contains(authorizationID(role: "recovery", key: $0)) }.count
        guard count >= Int(previous.descriptor.recovery.threshold) else {
            throw SiteIdentityError.invalid("transition lacks previous recovery threshold")
        }
    }

    static func decodeKeyList(_ encoded: [String], limit: Int) throws -> [Data] {
        guard encoded.count <= limit else { throw SiteIdentityError.invalid("key list exceeds bound") }
        return try encoded.map { try decodeCanonicalBase64($0, size: 32) }
    }

    static func decodeCanonicalBase64(_ encoded: String, size: Int) throws -> Data {
        guard let decoded = Data(base64Encoded: encoded), decoded.count == size, decoded.base64EncodedString() == encoded else {
            throw SiteIdentityError.malformed("base64 is not canonical or has wrong length")
        }
        return decoded
    }

    static func decodeCanonicalHex(_ encoded: String, size: Int) throws -> Data {
        guard encoded.count == size * 2, encoded == encoded.lowercased() else {
            throw SiteIdentityError.malformed("hex is not canonical or has wrong length")
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(size)
        var index = encoded.startIndex
        for _ in 0..<size {
            let next = encoded.index(index, offsetBy: 2)
            guard let byte = UInt8(encoded[index..<next], radix: 16) else {
                throw SiteIdentityError.malformed("hex contains invalid characters")
            }
            bytes.append(byte)
            index = next
        }
        let result = Data(bytes)
        guard result.hexString == encoded else {
            throw SiteIdentityError.malformed("hex has a non-canonical spelling")
        }
        return result
    }

    private static func canonicalDate(_ encoded: String) throws -> Date {
        guard encoded.count == 20, encoded.hasSuffix("Z") else {
            throw SiteIdentityError.malformed("time is not canonical UTC RFC3339")
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        guard let date = formatter.date(from: encoded), formatter.string(from: date) == encoded else {
            throw SiteIdentityError.malformed("time is not canonical UTC RFC3339")
        }
        return date
    }

    private static func authorizationID(role: String, key: Data) -> String {
        role + ":" + key.base64EncodedString()
    }

    private static func verifyEd25519(signature: Data, message: Data, key: Data) -> Bool {
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: key) else { return false }
        return publicKey.isValidSignature(signature, for: message)
    }

    private static func appendUInt32(_ value: UInt32, to out: inout Data) {
        var value = value.bigEndian
        withUnsafeBytes(of: &value) { out.append(contentsOf: $0) }
    }

    private static func appendUInt64(_ value: UInt64, to out: inout Data) {
        var value = value.bigEndian
        withUnsafeBytes(of: &value) { out.append(contentsOf: $0) }
    }

    private static func appendBytes(_ value: Data, to out: inout Data) {
        appendUInt64(UInt64(value.count), to: &out)
        out.append(value)
    }

    private static func appendString(_ value: String, to out: inout Data) {
        appendBytes(Data(value.utf8), to: &out)
    }

    private static func appendKeyList(_ keys: [Data], to out: inout Data) {
        appendUInt64(UInt64(keys.count), to: &out)
        for key in keys { appendBytes(key, to: &out) }
    }

    private static func readUInt64(_ data: Data, offset: Int) -> UInt64 {
        data[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
}
