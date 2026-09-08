import Foundation
import Testing
@testable import NomadBrowser

private let vectorSiteID = "4364fc878441b71500064023b7d0731ffcc4929b84240004bf2eb306d043c3cf"
private let vectorGenesisDigest = "cf4913523de3ce2d41bcc1110ff6966fcd3a94fd87e63c81537d1d1d1ccb74c1"
private let vectorRotationDigest = "1bfb37c21f897910c48bdd7f318dbfe71ff44f2d824b5b4d604d2cf2ddfb4a4c"

private func genesisVector() -> SiteDescriptor {
    SiteDescriptor(
        version: "nomad-site-descriptor-v1",
        siteID: vectorSiteID,
        sequence: 0,
        transition: "genesis",
        previousDescriptorDigest: String(repeating: "0", count: 64),
        validFrom: "2026-08-20T12:00:00Z",
        validUntil: "2027-08-20T12:00:00Z",
        signingKeys: [
            "3aLbAjR1OrV5CuxueN5bEhZGNCQEQGgxYueHV3rCgHg=",
            "PAiKczV5ucTOuvK/nBWg3twi5CQjxcRU2s8CqWc3Nhc="
        ],
        revokedKeys: [],
        recovery: SiteRecoveryPolicy(
            threshold: 2,
            keys: [
                "CU3x6jtwrwbJXk2Jx1qOVz9Uo12SekbYRUism3BNw7E=",
                "ApkGXtKVxmIuUegnoyhqLj5jN1I32weOiAglVodi2J4="
            ]
        ),
        authorizations: [
            SiteAuthorization(
                role: "signing",
                key: "3aLbAjR1OrV5CuxueN5bEhZGNCQEQGgxYueHV3rCgHg=",
                signature: "zV7NZRXZ7ualSSM77M0gklJ4XchbF0t/+yIIgnmeyiydvVo+8Bbm7i7PNu2ooF6Qpu2o7oOA5vRllJXjAjceBg=="
            ),
            SiteAuthorization(
                role: "signing",
                key: "PAiKczV5ucTOuvK/nBWg3twi5CQjxcRU2s8CqWc3Nhc=",
                signature: "fL5IS09A+KBFj7qr7iWDLTuWdeCGxJbJr0IKAt0imhkngYiorn6iLYCGm61qHoGZogdzbRpi7jhc8DF6mpWrBQ=="
            ),
            SiteAuthorization(
                role: "recovery",
                key: "CU3x6jtwrwbJXk2Jx1qOVz9Uo12SekbYRUism3BNw7E=",
                signature: "bCK+2nzItYZg44hEN1aazlCPiPN0lwYEldvC/+By6G6DnCStwCYr2lmmJ+1DvbJ00gHfsZ2wraXpvs+SyvsqAA=="
            ),
            SiteAuthorization(
                role: "recovery",
                key: "ApkGXtKVxmIuUegnoyhqLj5jN1I32weOiAglVodi2J4=",
                signature: "+a+zNwpb5Vtbfb5Su41UrzzrXoVTeGVjWkA82NhamIfNQ9N0u3P9qozaD8T6okv5MNL37SVyehrggbWbmuCHAw=="
            )
        ]
    )
}

private func rotationVector() -> SiteDescriptor {
    SiteDescriptor(
        version: "nomad-site-descriptor-v1",
        siteID: vectorSiteID,
        sequence: 1,
        transition: "rotation",
        previousDescriptorDigest: vectorGenesisDigest,
        validFrom: "2026-08-20T12:00:00Z",
        validUntil: "2027-08-20T12:00:00Z",
        signingKeys: ["7qWqXCqApajOVQRrAamckPfa+gMU+Ts4DfplpBz6kIo="],
        revokedKeys: [],
        recovery: SiteRecoveryPolicy(
            threshold: 2,
            keys: [
                "CU3x6jtwrwbJXk2Jx1qOVz9Uo12SekbYRUism3BNw7E=",
                "ApkGXtKVxmIuUegnoyhqLj5jN1I32weOiAglVodi2J4="
            ]
        ),
        authorizations: [
            SiteAuthorization(
                role: "signing",
                key: "3aLbAjR1OrV5CuxueN5bEhZGNCQEQGgxYueHV3rCgHg=",
                signature: "V9R45UErRHAxut32h6zzFWRMj4MaLju+58xzTIXmCW4KlmBbT4RsendJxIXQUdenNktKJbn0JFbaIU8uteQlDQ=="
            ),
            SiteAuthorization(
                role: "signing",
                key: "PAiKczV5ucTOuvK/nBWg3twi5CQjxcRU2s8CqWc3Nhc=",
                signature: "QHJU62HGGlrdvED34nD3CFIfrSwigXLvhlR2ejfENpniECI3f0aDYIc8nP8Ynul4Prp3Fd/tog5etTYKDpZnCA=="
            ),
            SiteAuthorization(
                role: "signing",
                key: "7qWqXCqApajOVQRrAamckPfa+gMU+Ts4DfplpBz6kIo=",
                signature: "m2+0F1Nh5lFSugC0SXf8uCPhJBDYRpe2o0FL9tu+2U8mwrY7Ew0cEZfEz3JCGLJmZ3DCXJwPvW/phQ6NjLyQCA=="
            )
        ]
    )
}

@Test("Swift derives the exact Go SiteID and descriptor digests")
func swiftMatchesGoSiteIdentityVectors() throws {
    let genesis = genesisVector()
    #expect(try SiteIdentityVerifier.deriveSiteID(genesis).hexString == vectorSiteID)
    #expect(try SiteIdentityVerifier.descriptorDigest(genesis).hexString == vectorGenesisDigest)
    #expect(try SiteIdentityVerifier.descriptorDigest(rotationVector()).hexString == vectorRotationDigest)
}

@Test("Swift verifies the Go genesis-to-rotation descriptor chain")
func swiftAcceptsGoDescriptorChain() throws {
    let chain = try SiteIdentityVerifier.verifyChain([genesisVector(), rotationVector()])
    #expect(chain.count == 2)
    #expect(chain[0].siteID.hexString == vectorSiteID)
    #expect(chain[0].digest.hexString == vectorGenesisDigest)
    #expect(chain[1].digest.hexString == vectorRotationDigest)
}

@Test("A validly encoded but transplanted authorization cannot survive a descriptor change")
func descriptorMutationInvalidatesAuthorizations() throws {
    let original = rotationVector()
    let mutated = SiteDescriptor(
        version: original.version,
        siteID: original.siteID,
        sequence: original.sequence,
        transition: original.transition,
        previousDescriptorDigest: original.previousDescriptorDigest,
        validFrom: original.validFrom,
        validUntil: "2027-08-21T12:00:00Z",
        signingKeys: original.signingKeys,
        revokedKeys: original.revokedKeys,
        recovery: original.recovery,
        authorizations: original.authorizations
    )
    #expect(throws: (any Error).self) {
        try SiteIdentityVerifier.verifyChain([genesisVector(), mutated])
    }
}

@Test("Non-canonical key encodings are rejected before signature evaluation")
func nonCanonicalSiteKeyEncodingFails() throws {
    let original = genesisVector()
    var signing = original.signingKeys
    signing[0] = "\n" + signing[0]
    let mutated = SiteDescriptor(
        version: original.version,
        siteID: original.siteID,
        sequence: original.sequence,
        transition: original.transition,
        previousDescriptorDigest: original.previousDescriptorDigest,
        validFrom: original.validFrom,
        validUntil: original.validUntil,
        signingKeys: signing,
        revokedKeys: original.revokedKeys,
        recovery: original.recovery,
        authorizations: original.authorizations
    )
    #expect(throws: (any Error).self) {
        try SiteIdentityVerifier.verifyChain([mutated])
    }
}
