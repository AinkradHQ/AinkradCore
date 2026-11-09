import Testing

@testable import AinkradClient

@Suite struct ServerSupportsTests {
    @Test func clientNewerThanServerUsesServersNewest() throws {
        #expect(try negotiateMinor(builtFor: 12, serverSupported: Array(0...11)) == 11)
    }

    @Test func clientOlderThanServerUsesItsOwn() throws {
        #expect(try negotiateMinor(builtFor: 3, serverSupported: Array(0...11)) == 3)
    }

    @Test func newestSharedMinorWinsRegardlessOfOrder() throws {
        #expect(try negotiateMinor(builtFor: 9, serverSupported: [2, 7, 0, 5]) == 7)
    }

    @Test func noOverlapStopsWithTypedError() {
        #expect(throws: NoSharedMinor(builtFor: 2, serverSupported: [5, 6])) {
            try negotiateMinor(builtFor: 2, serverSupported: [5, 6])
        }
    }

    @Test func garbageListsAreHandled() {
        for list: [Int32]? in [nil, [], [-1, -7]] {
            #expect(throws: NoSharedMinor.self) { try negotiateMinor(builtFor: 4, serverSupported: list) }
        }
        #expect((try? negotiateMinor(builtFor: 4, serverSupported: [-3, 2, 2, 99])) == 2)
    }

    @Test func handshakeHelper() throws {
        let h = Components.Schemas.Handshake(apiMinor: 11, supportedMinors: Array(0...11))
        #expect(h.serverSupports(minor: 11))
        #expect(!h.serverSupports(minor: 12))
        #expect(try h.negotiatedMinor(builtFor: 12) == 11)
        #expect(!Components.Schemas.Handshake().serverSupports(minor: 0), "no list means no support")
        let p = Components.Schemas.HandshakeProof(coreSig: "b", coreSpki: "a", supportedMinors: [0, 1])
        #expect(p.serverSupports(minor: 1) && !p.serverSupports(minor: 2))
    }
}
