import Foundation
import CryptoKit
import Testing
@testable import NomadBrowser

private func builtInEnvelopes() throws -> [SignedEnvelope] {
    let url = try #require(Bundle.module.url(forResource: "demo-catalog", withExtension: "json"))
    return try JSONDecoder().decode([SignedEnvelope].self, from: Data(contentsOf: url))
}

@Test("Every bundled object is exactly committed and Ed25519 verified without implying publisher identity")
func bundledObjectsVerify() throws {
    let envelopes = try builtInEnvelopes()
    #expect(envelopes.count == 3)
    for envelope in envelopes {
        let verified = try ObjectVerifier.verify(envelope)
        #expect(verified.publisherIdentity == .unknown)
        #expect(!verified.trustedPublisher)
        #expect(verified.siteID == nil)
        #expect(verified.id == envelope.contentHash)
    }
}

@Test("A payload mutation fails closed")
func payloadMutationFails() throws {
    let original = try #require(builtInEnvelopes().first)
    let mutated = SignedEnvelope(
        version: original.version,
        payload: original.payload + "A",
        contentHash: original.contentHash,
        publisherKey: original.publisherKey,
        signature: original.signature
    )
    #expect(throws: (any Error).self) {
        try ObjectVerifier.verify(mutated)
    }
}

@Test("A valid object signature from an unknown publisher proves integrity but not identity")
func unknownPublisherIsNotPromotedToTrusted() throws {
    let original = try #require(builtInEnvelopes().first)
    let payload = try #require(Data(base64Encoded: original.payload))
    let digest = Data(SHA256.hash(data: payload))
    let privateKey = Curve25519.Signing.PrivateKey()
    var message = ObjectVerifier.objectDomain
    message.append(digest)
    let signature = try privateKey.signature(for: message)
    let envelope = SignedEnvelope(
        version: 1,
        payload: original.payload,
        contentHash: digest.hexString,
        publisherKey: privateKey.publicKey.rawRepresentation.base64EncodedString(),
        signature: signature.base64EncodedString()
    )
    let verified = try ObjectVerifier.verify(envelope)
    #expect(verified.publisherIdentity == .unknown)
    #expect(!verified.trustedPublisher)
    #expect(verified.publisherFingerprint == String(Data(SHA256.hash(data: privateKey.publicKey.rawRepresentation)).hexString.prefix(16)))
}

@Test("Non-canonical base64 encodings are refused")
func nonCanonicalBase64Fails() throws {
    let original = try #require(builtInEnvelopes().first)
    let mutated = SignedEnvelope(
        version: original.version,
        payload: "\n" + original.payload,
        contentHash: original.contentHash,
        publisherKey: original.publisherKey,
        signature: original.signature
    )
    #expect(throws: ObjectVerificationError.malformedEncoding) {
        try ObjectVerifier.verify(mutated)
    }
}

@Test("Content hashes must use the canonical lowercase spelling")
func nonCanonicalContentHashFails() throws {
    let original = try #require(builtInEnvelopes().first)
    let mutated = SignedEnvelope(
        version: original.version,
        payload: original.payload,
        contentHash: original.contentHash.uppercased(),
        publisherKey: original.publisherKey,
        signature: original.signature
    )
    #expect(throws: ObjectVerificationError.commitmentMismatch) {
        try ObjectVerifier.verify(mutated)
    }
}

@Test("Local search ranks Selection Firewall without a network callback")
func localSearchWorks() throws {
    let documents = try builtInEnvelopes().map(ObjectVerifier.verify)
    let results = LocalSearchEngine.search("privat trafik selection firewall", documents: documents)
    #expect(results.first?.document.document.title == "Selection Firewall")
}

@Test("Empty and oversized queries are bounded")
func queriesAreBounded() throws {
    let documents = try builtInEnvelopes().map(ObjectVerifier.verify)
    #expect(LocalSearchEngine.search("   ", documents: documents).isEmpty)
    let query = String(repeating: "nomad ", count: 10_000)
    let results = LocalSearchEngine.search(query, documents: documents)
    #expect(!results.isEmpty)
}

@Test("Shared cache uses the exact Team-scoped browser-cache App Group from signed release configuration")
func sharedCacheUsesExactTeamScopedAppGroup() throws {
    let identifier = "ABCDE12345.nomad.browser-cache"
    let configured = try SharedCache.appGroupIdentifier(
        infoDictionary: [SharedCache.appGroupInfoKey: identifier]
    )
    #expect(configured == identifier)

    let container = URL(fileURLWithPath: "/tmp/nomad-browser-cache-test", isDirectory: true)
    var requestedIdentifier: String?
    let directory = try SharedCache.objectDirectory(identifier: configured) { requested in
        requestedIdentifier = requested
        return container
    }

    #expect(requestedIdentifier == identifier)
    #expect(directory == container.appendingPathComponent("objects", isDirectory: true))
}

@Test("Missing, malformed, or fabric-cache App Group configuration fails closed")
func invalidSharedCacheConfigurationFailsClosed() {
    #expect(throws: SharedCacheError.appGroupConfigurationMissing) {
        try SharedCache.appGroupIdentifier(infoDictionary: [:])
    }
    #expect(throws: SharedCacheError.invalidAppGroupIdentifier("group.io.nomad.shared")) {
        try SharedCache.appGroupIdentifier(
            infoDictionary: [SharedCache.appGroupInfoKey: "group.io.nomad.shared"]
        )
    }
    #expect(throws: SharedCacheError.invalidAppGroupIdentifier("ABCDE12345.nomad.fabric-cache")) {
        try SharedCache.appGroupIdentifier(
            infoDictionary: [SharedCache.appGroupInfoKey: "ABCDE12345.nomad.fabric-cache"]
        )
    }
    #expect(throws: SharedCacheError.invalidAppGroupIdentifier("short.nomad.browser-cache")) {
        try SharedCache.appGroupIdentifier(
            infoDictionary: [SharedCache.appGroupInfoKey: "short.nomad.browser-cache"]
        )
    }
}

@Test("Unavailable Team-scoped browser-cache App Group fails closed instead of falling back to private storage")
func missingSharedCacheFailsClosed() {
    let identifier = "ABCDE12345.nomad.browser-cache"
    #expect(throws: SharedCacheError.appGroupUnavailable(identifier)) {
        try SharedCache.objectDirectory(identifier: identifier) { _ in nil }
    }
}

@Test("Periodic local cache reload isolates malformed objects")
@MainActor
func liveCacheReloadIsFailClosedPerObject() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }

    let envelopes = try builtInEnvelopes()
    let store = NomadStore(objectDirectory: directory, includeBuiltIn: false)
    #expect(store.documents.isEmpty)

    let encoder = JSONEncoder()
    try encoder.encode(envelopes[0]).write(
        to: directory.appendingPathComponent("01.nomadobject"),
        options: .atomic
    )
    try Data("not-json".utf8).write(
        to: directory.appendingPathComponent("02.nomadobject"),
        options: .atomic
    )
    try encoder.encode(envelopes[1]).write(
        to: directory.appendingPathComponent("03.nomadobject"),
        options: .atomic
    )

    store.reload()
    #expect(store.documents.count == 2)
    #expect(store.rejectedObjectCount == 1)
    #expect(store.lastError == nil)
}
