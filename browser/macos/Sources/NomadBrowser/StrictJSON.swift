import Foundation

enum StrictJSONError: Error, Equatable {
    case invalidJSON
    case duplicateKey(String)
    case unknownOrMissingFields(String)
    case invalidShape(String)
}

enum StrictJSON {
    static func validateAndParse(_ data: Data) throws -> Any {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw StrictJSONError.invalidJSON
        }

        // Duplicate keys must be rejected before Foundation is allowed to
        // collapse an object to a dictionary. The scanner is intentionally
        // independent of JSONSerialization's duplicate-key policy.
        var scanner = DuplicateKeyScanner(data: data)
        try scanner.validate()
        return object
    }

    static func validateEnvelopeObject(_ object: Any) throws {
        guard let envelope = object as? [String: Any] else {
            throw StrictJSONError.invalidShape("signed envelope must be an object")
        }
        try exactKeys(
            envelope,
            required: ["version", "payload", "contentHash", "publisherKey", "signature"],
            optional: ["identity"],
            label: "signed envelope"
        )
        if let identity = envelope["identity"], !(identity is NSNull) {
            try validateIdentity(identity)
        }
    }

    static func validateEnvelopeCatalog(_ object: Any) throws {
        guard let catalog = object as? [Any] else {
            throw StrictJSONError.invalidShape("envelope catalog must be an array")
        }
        for envelope in catalog {
            try validateEnvelopeObject(envelope)
        }
    }

    static func validateDocumentPayload(_ data: Data) throws {
        let object = try validateAndParse(data)
        guard let document = object as? [String: Any] else {
            throw StrictJSONError.invalidShape("document payload must be an object")
        }
        try exactKeys(
            document,
            required: ["title", "summary", "body", "tags", "publishedAt", "publisherName", "mediaType"],
            optional: [],
            label: "document payload"
        )
    }

    private static func validateIdentity(_ object: Any) throws {
        guard let identity = object as? [String: Any] else {
            throw StrictJSONError.invalidShape("identity must be an object")
        }
        try exactKeys(
            identity,
            required: ["descriptors", "publication", "manifest"],
            optional: [],
            label: "identity"
        )
        guard let descriptors = identity["descriptors"] as? [Any] else {
            throw StrictJSONError.invalidShape("identity descriptors must be an array")
        }
        guard !descriptors.isEmpty, descriptors.count <= SiteIdentityVerifier.maxDescriptors else {
            throw StrictJSONError.invalidShape("identity descriptor chain is empty or too long")
        }
        for descriptor in descriptors {
            try validateDescriptor(descriptor)
        }
        guard let publication = identity["publication"] else {
            throw StrictJSONError.invalidShape("identity publication is missing")
        }
        try validatePublication(publication)
    }

    private static func validateDescriptor(_ object: Any) throws {
        guard let descriptor = object as? [String: Any] else {
            throw StrictJSONError.invalidShape("site descriptor must be an object")
        }
        try exactKeys(
            descriptor,
            required: [
                "version", "site_id", "sequence", "transition", "previous_descriptor_digest",
                "valid_from", "valid_until", "signing_keys", "revoked_keys", "recovery", "authorizations"
            ],
            optional: [],
            label: "site descriptor"
        )
        guard let recovery = descriptor["recovery"] as? [String: Any] else {
            throw StrictJSONError.invalidShape("site recovery policy must be an object")
        }
        try exactKeys(
            recovery,
            required: ["threshold", "keys"],
            optional: [],
            label: "site recovery policy"
        )
        guard let authorizations = descriptor["authorizations"] as? [Any],
              authorizations.count <= SiteIdentityVerifier.maxAuthorizations else {
            throw StrictJSONError.invalidShape("site authorizations are not a bounded array")
        }
        for authorization in authorizations {
            guard let authorization = authorization as? [String: Any] else {
                throw StrictJSONError.invalidShape("site authorization must be an object")
            }
            try exactKeys(
                authorization,
                required: ["role", "key", "signature"],
                optional: [],
                label: "site authorization"
            )
        }
    }

    private static func validatePublication(_ object: Any) throws {
        guard let publication = object as? [String: Any] else {
            throw StrictJSONError.invalidShape("site publication must be an object")
        }
        try exactKeys(
            publication,
            required: [
                "version", "site_id", "descriptor_digest", "signing_key", "object_root",
                "manifest_digest", "published_at", "signature"
            ],
            optional: [],
            label: "site publication"
        )
    }

    private static func exactKeys(
        _ object: [String: Any],
        required: Set<String>,
        optional: Set<String>,
        label: String
    ) throws {
        let actual = Set(object.keys)
        guard required.isSubset(of: actual), actual.isSubset(of: required.union(optional)) else {
            throw StrictJSONError.unknownOrMissingFields(label)
        }
    }
}

enum SignedEnvelopeDecoder {
    static func decode(_ data: Data) throws -> SignedEnvelope {
        let object = try StrictJSON.validateAndParse(data)
        try StrictJSON.validateEnvelopeObject(object)
        do {
            return try JSONDecoder().decode(SignedEnvelope.self, from: data)
        } catch {
            throw StrictJSONError.invalidShape("signed envelope types are invalid")
        }
    }

    static func decodeCatalog(_ data: Data) throws -> [SignedEnvelope] {
        let object = try StrictJSON.validateAndParse(data)
        try StrictJSON.validateEnvelopeCatalog(object)
        do {
            return try JSONDecoder().decode([SignedEnvelope].self, from: data)
        } catch {
            throw StrictJSONError.invalidShape("envelope catalog types are invalid")
        }
    }
}

private struct DuplicateKeyScanner {
    private let bytes: [UInt8]
    private var index = 0

    init(data: Data) {
        bytes = Array(data)
    }

    mutating func validate() throws {
        skipWhitespace()
        try parseValue()
        skipWhitespace()
        guard index == bytes.count else {
            throw StrictJSONError.invalidJSON
        }
    }

    private mutating func parseValue() throws {
        skipWhitespace()
        guard index < bytes.count else {
            throw StrictJSONError.invalidJSON
        }
        switch bytes[index] {
        case 0x7b: try parseObject() // {
        case 0x5b: try parseArray()  // [
        case 0x22: _ = try parseString()
        case 0x74: try consumeLiteral("true")
        case 0x66: try consumeLiteral("false")
        case 0x6e: try consumeLiteral("null")
        default: try parseNumber()
        }
    }

    private mutating func parseObject() throws {
        index += 1
        skipWhitespace()
        var keys = Set<String>()
        if consumeIf(0x7d) { return }

        while true {
            skipWhitespace()
            guard index < bytes.count, bytes[index] == 0x22 else {
                throw StrictJSONError.invalidJSON
            }
            let key = try parseString()
            guard keys.insert(key).inserted else {
                throw StrictJSONError.duplicateKey(key)
            }
            skipWhitespace()
            guard consumeIf(0x3a) else {
                throw StrictJSONError.invalidJSON
            }
            try parseValue()
            skipWhitespace()
            if consumeIf(0x7d) { return }
            guard consumeIf(0x2c) else {
                throw StrictJSONError.invalidJSON
            }
        }
    }

    private mutating func parseArray() throws {
        index += 1
        skipWhitespace()
        if consumeIf(0x5d) { return }

        while true {
            try parseValue()
            skipWhitespace()
            if consumeIf(0x5d) { return }
            guard consumeIf(0x2c) else {
                throw StrictJSONError.invalidJSON
            }
        }
    }

    private mutating func parseString() throws -> String {
        let start = index
        guard consumeIf(0x22) else {
            throw StrictJSONError.invalidJSON
        }
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if escaped {
                escaped = false
                continue
            }
            if byte == 0x5c {
                escaped = true
                continue
            }
            if byte == 0x22 {
                let rawString = Data(bytes[start..<index])
                do {
                    // Decoding the isolated JSON string makes escaped-equivalent
                    // spellings (for example "site_id" and "site_\u0069d")
                    // compare as the same semantic object key.
                    return try JSONDecoder().decode(String.self, from: rawString)
                } catch {
                    throw StrictJSONError.invalidJSON
                }
            }
            if byte < 0x20 {
                throw StrictJSONError.invalidJSON
            }
        }
        throw StrictJSONError.invalidJSON
    }

    private mutating func parseNumber() throws {
        let start = index
        while index < bytes.count, isNumberByte(bytes[index]) {
            index += 1
        }
        // JSONSerialization already established that the token is a valid JSON
        // number. This scanner only has to consume the same token boundary.
        guard index > start else {
            throw StrictJSONError.invalidJSON
        }
    }

    private func isNumberByte(_ byte: UInt8) -> Bool {
        byte == 0x2d || byte == 0x2b || byte == 0x2e || byte == 0x45 || byte == 0x65 ||
            (0x30...0x39).contains(byte)
    }

    private mutating func consumeLiteral(_ literal: String) throws {
        let literalBytes = Array(literal.utf8)
        guard index + literalBytes.count <= bytes.count,
              Array(bytes[index..<(index + literalBytes.count)]) == literalBytes else {
            throw StrictJSONError.invalidJSON
        }
        index += literalBytes.count
    }

    private mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) {
            index += 1
        }
    }

    private mutating func consumeIf(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else {
            return false
        }
        index += 1
        return true
    }
}
