// Hand-written (not generated): API minor negotiation, handshake spec section on versioning.
// A client built for minor N+1 talks to a server at N by using only what minor N has.

/// The client and server share no API minor, so the client must stop.
public struct NoSharedMinor: Error, Equatable, Sendable {
    public let builtFor: Int32
    public let serverSupported: [Int32]
}

/// A server that lists no usable minors (absent, empty or only negative values) supports nothing.
public func negotiateMinor(builtFor: Int32, serverSupported: [Int32]?) throws -> Int32 {
    // A client built for minor M speaks every minor 0...M; the newest one the server also lists wins.
    guard let best = (serverSupported ?? []).filter({ $0 >= 0 && $0 <= builtFor }).max() else {
        throw NoSharedMinor(builtFor: builtFor, serverSupported: serverSupported ?? [])
    }
    return best
}

extension Components.Schemas.Handshake {
    /// Whether the server serves `minor`. False when it did not list `supported_minors`.
    public func serverSupports(minor: Int32) -> Bool { supportedMinors?.contains(minor) ?? false }
    public func negotiatedMinor(builtFor: Int32) throws -> Int32 {
        try negotiateMinor(builtFor: builtFor, serverSupported: supportedMinors)
    }
}

extension Components.Schemas.HandshakeProof {
    public func serverSupports(minor: Int32) -> Bool { supportedMinors?.contains(minor) ?? false }
    public func negotiatedMinor(builtFor: Int32) throws -> Int32 {
        try negotiateMinor(builtFor: builtFor, serverSupported: supportedMinors)
    }
}
