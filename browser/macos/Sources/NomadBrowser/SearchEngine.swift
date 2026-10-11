import CryptoKit
import Foundation

struct SearchResult: Identifiable, Sendable {
    let document: VerifiedDocument
    let score: Double
    var id: String { document.id }
}

enum LocalSearchEngine {
    static let maximumQueryCharacters = 512
    static let maximumSearchableBodyCharacters = 32_768

    static func search(_ rawQuery: String, documents: [VerifiedDocument]) -> [SearchResult] {
        let query = String(rawQuery.prefix(maximumQueryCharacters))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return [] }
        let queryTokens = tokens(query)
        guard !queryTokens.isEmpty else { return [] }
        let queryBasin = basin(queryTokens)

        return documents.compactMap { verified in
            let document = verified.document
            let titleTokens = tokens(document.title)
            let tagTokens = tokens(document.tags.joined(separator: " "))
            let summaryTokens = tokens(document.summary)
            let bodyTokens = tokens(String(document.body.prefix(maximumSearchableBodyCharacters)))
            let lexical = overlap(queryTokens, titleTokens) * 8
                + overlap(queryTokens, tagTokens) * 5
                + overlap(queryTokens, summaryTokens) * 3
                + overlap(queryTokens, bodyTokens)
            let documentBasin = basin(titleTokens + tagTokens + summaryTokens + bodyTokens)
            let semantic = Double(64 - (queryBasin ^ documentBasin).nonzeroBitCount) / 64.0
            let phraseBoost = document.title.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
                .contains(query.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)) ? 12.0 : 0.0
            let score = Double(lexical) + semantic + phraseBoost
            guard lexical > 0 || phraseBoost > 0 else { return nil }
            return SearchResult(document: verified, score: score)
        }
        .sorted {
            if $0.score != $1.score { return $0.score > $1.score }
            return $0.document.document.title.localizedStandardCompare($1.document.document.title) == .orderedAscending
        }
    }

    static func tokens(_ text: String) -> [String] {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "sv_SE"))
            .split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map(String.init)
            .filter { $0.count >= 2 }
    }

    static func overlap(_ query: [String], _ candidate: [String]) -> Int {
        let querySet = Set(query)
        let candidateSet = Set(candidate)
        return querySet.intersection(candidateSet).count
    }

    static func basin(_ tokens: [String]) -> UInt64 {
        guard !tokens.isEmpty else { return 0 }
        var accumulators = Array(repeating: 0, count: 64)
        for token in Set(tokens) {
            let digest = Array(SHA256.hash(data: Data(token.utf8)))
            for bit in 0..<64 {
                let byte = digest[bit / 8]
                accumulators[bit] += ((byte >> (bit % 8)) & 1) == 1 ? 1 : -1
            }
        }
        return accumulators.enumerated().reduce(UInt64(0)) { value, item in
            item.element >= 0 ? value | (UInt64(1) << UInt64(item.offset)) : value
        }
    }
}
