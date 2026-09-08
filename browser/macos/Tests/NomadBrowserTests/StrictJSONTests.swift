import Foundation
import Testing
@testable import NomadBrowser

@Test("Duplicate envelope keys are rejected before Codable chooses a value")
func duplicateEnvelopeKeyFails() {
    let encoded = Data(#"{"version":1,"version":2,"payload":"AA==","contentHash":"00","publisherKey":"AA==","signature":"AA=="}"#.utf8)
    #expect(throws: StrictJSONError.duplicateKey("version")) {
        try SignedEnvelopeDecoder.decode(encoded)
    }
}

@Test("Unknown envelope fields are rejected instead of ignored")
func unknownEnvelopeFieldFails() {
    let encoded = Data(#"{"version":1,"payload":"AA==","contentHash":"00","publisherKey":"AA==","signature":"AA==","networkFallback":"https://example.invalid"}"#.utf8)
    #expect(throws: StrictJSONError.unknownOrMissingFields("signed envelope")) {
        try SignedEnvelopeDecoder.decode(encoded)
    }
}

@Test("Duplicate nested SiteID fields are rejected")
func duplicateNestedSiteFieldFails() {
    let encoded = Data(#"{"version":1,"payload":"AA==","contentHash":"00","publisherKey":"AA==","signature":"AA==","identity":{"descriptors":[{"version":"nomad-site-descriptor-v1","site_id":"00","site_id":"11","sequence":0,"transition":"genesis","previous_descriptor_digest":"00","valid_from":"2026-08-20T12:00:00Z","valid_until":"2027-08-20T12:00:00Z","signing_keys":[],"revoked_keys":[],"recovery":{"threshold":1,"keys":[]},"authorizations":[]}],"publication":{"version":"nomad-site-publication-v1","site_id":"00","descriptor_digest":"00","signing_key":"AA==","object_root":"00","manifest_digest":"00","published_at":"2026-08-20T13:00:00Z","signature":"AA=="},"manifest":"AA=="}}"#.utf8)
    #expect(throws: StrictJSONError.duplicateKey("site_id")) {
        try SignedEnvelopeDecoder.decode(encoded)
    }
}

@Test("Document payload schema is exact and does not ignore injected fields")
func unknownDocumentFieldFails() {
    let encoded = Data(#"{"title":"x","summary":"","body":"","tags":[],"publishedAt":"2026-08-20T12:00:00Z","publisherName":"x","mediaType":"text/plain; charset=utf-8","url":"https://example.invalid"}"#.utf8)
    #expect(throws: StrictJSONError.unknownOrMissingFields("document payload")) {
        try StrictJSON.validateDocumentPayload(encoded)
    }
}

@Test("Duplicate document keys are rejected before local rendering")
func duplicateDocumentFieldFails() {
    let encoded = Data(#"{"title":"safe","title":"other","summary":"","body":"","tags":[],"publishedAt":"2026-08-20T12:00:00Z","publisherName":"x","mediaType":"text/plain; charset=utf-8"}"#.utf8)
    #expect(throws: StrictJSONError.duplicateKey("title")) {
        try StrictJSON.validateDocumentPayload(encoded)
    }
}
