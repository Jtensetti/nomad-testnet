import Combine
import Foundation

@MainActor
final class NomadStore: ObservableObject {
    static let maximumObjects = 256
    static let maximumEncodedEnvelopeBytes = 400_000
    static let publicCacheRefreshInterval: TimeInterval = 5

    @Published private(set) var documents: [VerifiedDocument] = []
    @Published private(set) var rejectedObjectCount = 0
    @Published private(set) var lastError: String?

    private let objectDirectoryOverride: URL?
    private let includeBuiltIn: Bool

    init(objectDirectory: URL? = nil, includeBuiltIn: Bool = true) {
        objectDirectoryOverride = objectDirectory
        self.includeBuiltIn = includeBuiltIn
        reload()
    }

    func reload() {
        var envelopes: [SignedEnvelope] = []
        var rejected = 0
        lastError = nil

        if includeBuiltIn {
            do {
                guard let builtInURL = Bundle.module.url(forResource: "demo-catalog", withExtension: "json") else {
                    throw CocoaError(.fileNoSuchFile)
                }
                let data = try Self.boundedData(at: builtInURL)
                envelopes.append(contentsOf: try SignedEnvelopeDecoder.decodeCatalog(data))
            } catch {
                lastError = error.localizedDescription
            }
        }

        do {
            let disk = try diskEnvelopes()
            envelopes.append(contentsOf: disk.envelopes)
            rejected += disk.rejected
        } catch {
            // A production browser must not silently fall back to its private
            // Application Support directory when the shared process boundary is
            // absent. Doing so would make a broken materializer/App Group setup
            // look functional while bypassing the reviewed cross-process path.
            lastError = error.localizedDescription
        }

        var accepted: [String: VerifiedDocument] = [:]
        for envelope in envelopes.prefix(Self.maximumObjects) {
            do {
                let verified = try ObjectVerifier.verify(envelope)
                accepted[verified.id] = verified
            } catch {
                rejected += 1
            }
        }
        documents = accepted.values.sorted {
            $0.document.title.localizedStandardCompare($1.document.title) == .orderedAscending
        }
        rejectedObjectCount = rejected
    }

    private func diskEnvelopes() throws -> (envelopes: [SignedEnvelope], rejected: Int) {
        let manager = FileManager.default
        let objectDirectory: URL
        if let objectDirectoryOverride {
            // Test-only / dependency-injected path. Production initialization
            // passes nil and therefore must use the shared App Group container.
            objectDirectory = objectDirectoryOverride
        } else {
            objectDirectory = try SharedCache.objectDirectory()
        }

        // The browser is deliberately a read-only participant in the shared
        // cache protocol. The materializer owns directory/object creation. If
        // nothing has been materialized yet, absence means an empty cache; the
        // browser must not create, repair or otherwise signal through the shared
        // filesystem.
        var isDirectory: ObjCBool = false
        guard manager.fileExists(atPath: objectDirectory.path, isDirectory: &isDirectory) else {
            return ([], 0)
        }
        guard isDirectory.boolValue else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }

        let files = try manager.contentsOfDirectory(
            at: objectDirectory,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        )
        let candidates = files
            .filter { $0.pathExtension == "nomadobject" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .prefix(Self.maximumObjects)
        var envelopes: [SignedEnvelope] = []
        var rejected = 0
        for file in candidates {
            do {
                envelopes.append(try SignedEnvelopeDecoder.decode(Self.boundedData(at: file)))
            } catch {
                // One hostile or partially written object must not suppress the
                // other immutable cache entries.
                rejected += 1
            }
        }
        return (envelopes, rejected)
    }

    private static func boundedData(at url: URL) throws -> Data {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        guard let size = values.fileSize, size <= Self.maximumEncodedEnvelopeBytes else {
            throw ObjectVerificationError.objectTooLarge
        }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe, .uncached])
        guard data.count <= Self.maximumEncodedEnvelopeBytes else {
            throw ObjectVerificationError.objectTooLarge
        }
        return data
    }
}
