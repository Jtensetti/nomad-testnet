import Foundation

enum SharedCacheError: Error, Equatable {
    case appGroupConfigurationMissing
    case invalidAppGroupIdentifier(String)
    case appGroupUnavailable(String)
}

enum SharedCache {
    // build_dmg.sh writes this key into the signed app's Info.plist from the
    // same Team ID used to generate the application-groups entitlement. It is
    // release configuration, not a user preference.
    //
    // The browser belongs only to the browser-cache group. The network domain
    // uses a different fabric-cache group; only the networkless materializer is
    // allowed to bridge from fabric-cache to browser-cache.
    static let appGroupInfoKey = "NomadAppGroupIdentifier"
    static let appGroupSuffix = ".nomad.browser-cache"
    static let objectDirectoryName = "objects"

    static func appGroupIdentifier(
        infoDictionary: [String: Any]? = Bundle.main.infoDictionary
    ) throws -> String {
        guard let identifier = infoDictionary?[appGroupInfoKey] as? String else {
            throw SharedCacheError.appGroupConfigurationMissing
        }
        guard isTeamScopedIdentifier(identifier) else {
            throw SharedCacheError.invalidAppGroupIdentifier(identifier)
        }
        return identifier
    }

    static func objectDirectory() throws -> URL {
        let identifier = try appGroupIdentifier()
        return try objectDirectory(identifier: identifier) { requestedIdentifier in
            FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: requestedIdentifier
            )
        }
    }

    // The resolver is injected only so tests can prove exact-path and
    // fail-closed behavior without requiring a provisioned Developer ID team on
    // the test runner. Production always uses FileManager.containerURL above.
    static func objectDirectory(
        identifier: String,
        resolveContainer: (String) -> URL?
    ) throws -> URL {
        guard isTeamScopedIdentifier(identifier) else {
            throw SharedCacheError.invalidAppGroupIdentifier(identifier)
        }
        guard let container = resolveContainer(identifier) else {
            throw SharedCacheError.appGroupUnavailable(identifier)
        }
        return container.appendingPathComponent(objectDirectoryName, isDirectory: true)
    }

    private static func isTeamScopedIdentifier(_ identifier: String) -> Bool {
        guard identifier.hasSuffix(appGroupSuffix) else { return false }
        let team = String(identifier.dropLast(appGroupSuffix.count))
        guard team.utf8.count == 10 else { return false }
        return team.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
        }
    }
}
