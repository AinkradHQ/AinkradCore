import Foundation
import Testing

@testable import AinkradClient

// Recorded server responses decoded by the generated types: a field the generator or the server
// renames or retypes fails here before a UI does. The date strategy matches the wire shape
// (RFC 3339 UTC with milliseconds).
private func decode<T: Decodable>(_ type: T.Type, _ fixture: String) throws -> T {
    let url = try #require(Bundle.module.url(forResource: fixture, withExtension: "json", subdirectory: "Fixtures"))
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .custom { decoder in
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let date = formatter.date(from: text) else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: text))
        }
        return date
    }
    return try decoder.decode(type, from: Data(contentsOf: url))
}

@Suite struct FixtureDecodeTests {
    @Test func meDecodes() throws {
        let me = try decode(Components.Schemas.Me.self, "me")
        #expect(me.device.id == "d_3v8c2q0k5n7m1p4r6t9w2x5z8b")
        #expect(me.versions.server == "0.1.0")
        #expect(me.versions.api.major == "v1")
        #expect(me.versions.api.minor == 0)
    }

    @Test func deviceListDecodesAndToleratesUnknownFields() throws {
        let devices = try decode([Components.Schemas.Device].self, "devices")
        #expect(devices.map(\.name) == ["Ahmed's Mac", "iPhone"])
        #expect(devices[0].revokedAt == nil)
        #expect(devices[1].revokedAt != nil)
        #expect(devices[0].kind == "device")
        #expect(devices[0].scopes == ["read", "admin"])
        #expect(devices[1].kind == nil, "new fields are optional")
    }
}
