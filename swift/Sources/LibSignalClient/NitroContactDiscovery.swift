// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Security

/// A complete CDSI transport for the LetKnow Nitro service.
/// Configuration must come from a trusted release, including PCRs and any private TLS root.
@available(iOS 15.0, macOS 12.0, *)
public final class NitroContactDiscovery: Sendable {
    public enum Failure: Error, Sendable {
        case invalidToken
        case unauthorized
        case rateLimited(retryAfterSeconds: Int)
        case unavailable
    }
    public struct AccessKey: Sendable {
        public let aci: UUID
        public let key: Data
        public init(aci: UUID, key: Data) throws {
            guard key.count == 16 else { throw SignalError.invalidArgument("UAK must contain 16 bytes") }
            self.aci = aci
            self.key = key
        }
    }
    public struct Record: Sendable {
        public let e164: UInt64
        public let pni: UUID?
        public let aci: UUID?
    }
    public struct Result: Sendable {
        public let records: [Record]
        public let token: Data
        public let permitsUsed: UInt64
    }
    private let endpoint: URL
    private let expectedPcrs: Data
    private let tlsRootCertificate: Data?

    /// The LetKnow stage service and its reviewed enclave image, released 7 October 2026.
    /// Update this policy with a new SDK release whenever the enclave image changes.
    public static func letKnowStage() throws -> NitroContactDiscovery {
        try NitroContactDiscovery(
            endpoint: URL(string: "wss://chat.stage.letknow.info:8443/v1/nitro/discovery")!,
            expectedPcrs: Data(base64Encoded: "8O1UT3bHna2fcy6s0fqNVjgBxOBkeyRsEc8HxQMmB4cInSX6xr3hLFSMfzapc5frS01bNmGz78EpIJAMgOEm5M54PFIt5sAqKlv3rzorkye4Z3bxiOS+HBxAShKdvaSTfEHk4Eu70WkpG+AMwE7FXhxktuZ7CeEGn/5DnCMfeXbYOibmE2JIE4D1zegRC4QS")!,
            tlsRootCertificate: Data(base64Encoded: "MIIBdDCCARqgAwIBAgIQTrYorRxuage2TJxBV9isOjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9MZXRLbm93IFJvb3QgQ0EwHhcNMjYwOTE5MTE1NDM1WhcNMzYwOTE2MTE1NDM1WjAaMRgwFgYDVQQDDA9MZXRLbm93IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATysbi0IGsvGSzEtu6tJaPcLoTa5SsRS5dJOPpn9RfvZwHvSj3SfzB06prt/QdFzk+6BfVn37ugzt0Yvt9Nv/kro0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUeNIjDZ4t36dNkiuF0vsCjDOp6lwwCgYIKoZIzj0EAwIDSAAwRQIgWvb8WZDf3WwzslCob4TFOuPLkBSdJHj8++uFMl5i6I0CIQC9mcYd97sLvsQb9dv2zBzIfXxdFXzooTTkc6iACxC5Nw==")!
        )
    }

    /// `tlsRootCertificate` is an optional DER certificate for a private CA.
    /// Hostname and certificate validity checks remain mandatory.
    public init(endpoint: URL, expectedPcrs: Data, tlsRootCertificate: Data? = nil) throws {
        guard endpoint.scheme == "wss", endpoint.host != nil,
              endpoint.user == nil, endpoint.password == nil,
              endpoint.query == nil, endpoint.fragment == nil,
              endpoint.path == "/v1/nitro/discovery", expectedPcrs.count == 144
        else { throw SignalError.invalidArgument("Invalid Nitro endpoint or PCR policy") }
        for offset in stride(from: 0, to: 144, by: 48) {
            guard expectedPcrs[offset..<offset + 48].contains(where: { $0 != 0 }) else {
                throw SignalError.invalidArgument("Debug enclave measurements are forbidden")
            }
        }
        if let root = tlsRootCertificate, SecCertificateCreateWithData(nil, root as CFData) == nil {
            throw SignalError.invalidArgument("Invalid TLS root certificate")
        }
        self.endpoint = endpoint
        self.expectedPcrs = expectedPcrs
        self.tlsRootCertificate = tlsRootCertificate
    }

    /// Credentials come from the chat server's Directory V2 authentication endpoint.
    /// Persist the new token in `onToken` before returning from that callback.
    /// Reuse it with all previous numbers, moving removed numbers to `discardE164s`.
    public func lookup(
        username: String, password: String,
        newE164s: [UInt64], previousE164s: [UInt64] = [], discardE164s: [UInt64] = [],
        accessKeys: [AccessKey] = [], token: Data = Data(),
        onToken: @Sendable (Data) async throws -> Void
    ) async throws -> Result {
        let requested = previousE164s + newE164s
        guard !requested.isEmpty, requested.count <= 1000,
              previousE164s.count + discardE164s.count <= 1000, accessKeys.count <= 1000,
              (requested + discardE164s).allSatisfy({ (1...999_999_999_999_999).contains($0) }),
              token.isEmpty || token.count == 65,
              !username.isEmpty, username.utf8.count <= 128, !username.contains(":"),
              password.utf8.count <= 256
        else { throw SignalError.invalidArgument("Invalid CDSI request") }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 45
        let delegate = NitroTLSDelegate(host: endpoint.host!, root: tlsRootCertificate)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        var request = URLRequest(url: endpoint)
        request.setValue("Basic " + Data("\(username):\(password)".utf8).base64EncodedString(), forHTTPHeaderField: "Authorization")
        let socket = session.webSocketTask(with: request)
        socket.maximumMessageSize = 65536
        socket.resume()
        defer {
            socket.cancel(with: .normalClosure, reason: nil)
            session.invalidateAndCancel()
        }
        do {
            return try await withTaskCancellationHandler {
                let challenge = try NitroCds2Client.makeChallenge()
                try await socket.send(.data(challenge))
                let client = try NitroCds2Client(
                    expectedPcrs: expectedPcrs, challenge: challenge,
                    attestationMessage: try await Self.receive(socket)
                )
                try await socket.send(.data(client.initialRequest()))
                try client.completeHandshake(try await Self.receive(socket))
                var pairs = Data()
                for access in accessKeys {
                    var uuid = access.aci.uuid
                    pairs.append(withUnsafeBytes(of: &uuid) { Data($0) })
                    pairs.append(access.key)
                }
                let plaintext = NitroCdsiWire.bytes(1, pairs)
                    + NitroCdsiWire.bytes(2, Self.numbers(previousE164s))
                    + NitroCdsiWire.bytes(3, Self.numbers(newE164s))
                    + NitroCdsiWire.bytes(4, Self.numbers(discardE164s))
                    + NitroCdsiWire.bytes(6, token)
                try await socket.send(.data(client.establishedSend(plaintext)))
                let prepared = try NitroCdsiWire.decode(client.establishedRecv(try await Self.receive(socket)))
                guard prepared.token.count == 65, prepared.triples.isEmpty else {
                    throw SignalError.invalidMessage("Invalid CDSI token response")
                }
                try await onToken(prepared.token)
                try Task.checkCancellation()
                try await socket.send(.data(client.establishedSend(Data([0x38, 0x01]))))
                let response = try NitroCdsiWire.decode(client.establishedRecv(try await Self.receive(socket)))
                guard response.triples.count == requested.count * 40, response.token.isEmpty else {
                    throw SignalError.invalidMessage("Invalid CDSI response size")
                }
                var records: [Record] = []
                for (index, phone) in requested.enumerated() {
                    let offset = index * 40
                    let number = response.triples[offset..<offset + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                    guard number == phone else { throw SignalError.invalidMessage("CDSI response order mismatch") }
                    records.append(Record(
                        e164: phone,
                        pni: Self.uuid(Data(response.triples[offset + 8..<offset + 24])),
                        aci: Self.uuid(Data(response.triples[offset + 24..<offset + 40]))
                    ))
                }
                return Result(records: records, token: prepared.token, permitsUsed: response.permits)
            } onCancel: {
                socket.cancel(with: .goingAway, reason: nil)
            }
        } catch {
            throw Self.mappedFailure(error, socket: socket)
        }
    }
    private static func receive(_ socket: URLSessionWebSocketTask) async throws -> Data {
        guard case .data(let bytes) = try await socket.receive(), bytes.count <= 65536 else {
            throw SignalError.invalidMessage("Expected a binary CDSI frame")
        }
        return bytes
    }
    private static func mappedFailure(_ error: Error, socket: URLSessionWebSocketTask) -> Error {
        if let response = socket.response as? HTTPURLResponse {
            if response.statusCode == 401 { return Failure.unauthorized }
            if response.statusCode == 429 {
                let delay = Int(response.value(forHTTPHeaderField: "Retry-After") ?? "") ?? 60
                return Failure.rateLimited(retryAfterSeconds: max(1, min(delay, 86400)))
            }
            if response.statusCode == 503 { return Failure.unavailable }
        }
        switch socket.closeCode.rawValue {
        case 4101: return Failure.invalidToken
        case 1013, 4115: return Failure.unavailable
        case 4008:
            let reason = socket.closeReason.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Int]
            return Failure.rateLimited(retryAfterSeconds: max(1, min(reason?["retry_after"] ?? 60, 86400)))
        default: return error
        }
    }
    private static func numbers(_ values: [UInt64]) -> Data {
        values.reduce(into: Data()) { result, number in
            var bigEndian = number.bigEndian
            result.append(withUnsafeBytes(of: &bigEndian) { Data($0) })
        }
    }
    private static func uuid(_ bytes: Data) -> UUID? {
        guard bytes.contains(where: { $0 != 0 }) else { return nil }
        return bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
}

private final class NitroTLSDelegate: NSObject, URLSessionDelegate, Sendable {
    let host: String
    let root: Data?
    init(host: String, root: Data?) { self.host = host; self.root = root }
    func urlSession(
        _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let root else { completionHandler(.performDefaultHandling, nil); return }
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == host,
              let trust = challenge.protectionSpace.serverTrust,
              let certificate = SecCertificateCreateWithData(nil, root as CFData),
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [certificate] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil)
        else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

enum NitroCdsiWire {
    struct Response { var triples = Data(); var token = Data(); var permits: UInt64 = 0 }
    static func bytes(_ field: UInt8, _ value: Data) -> Data {
        guard !value.isEmpty else { return Data() }
        var result = Data([field << 3 | 2])
        var length = value.count
        while length >= 128 { result.append(UInt8(length & 127) | 128); length >>= 7 }
        result.append(UInt8(length))
        return result + value
    }
    static func decode(_ data: Data) throws -> Response {
        let bytes = [UInt8](data)
        guard bytes.count <= 65536 else { throw SignalError.invalidMessage("CDSI message too large") }
        var position = 0
        func varint() throws -> UInt64 {
            var value: UInt64 = 0
            for shift in stride(from: 0, through: 63, by: 7) {
                guard position < bytes.count else { throw SignalError.invalidMessage("Truncated protobuf") }
                let byte = bytes[position]; position += 1
                guard shift != 63 || byte <= 1 else { throw SignalError.invalidMessage("Protobuf integer overflow") }
                value |= UInt64(byte & 127) << shift
                if byte & 128 == 0 { return value }
            }
            throw SignalError.invalidMessage("Invalid protobuf integer")
        }
        var response = Response()
        var seen = Set<UInt64>()
        while position < bytes.count {
            let tag = try varint(), field = tag >> 3, wire = tag & 7
            guard field > 0 else { throw SignalError.invalidMessage("Invalid protobuf field") }
            if [1, 3, 4].contains(field) {
                guard seen.insert(field).inserted else { throw SignalError.invalidMessage("Duplicate CDSI field") }
                guard wire == (field == 4 ? 0 : 2) else { throw SignalError.invalidMessage("Wrong CDSI field type") }
            }
            switch wire {
            case 0:
                let value = try varint()
                if field == 4 { response.permits = value }
            case 1, 2, 5:
                let count = wire == 2 ? try varint() : (wire == 1 ? 8 : 4)
                guard count <= UInt64(bytes.count - position) else { throw SignalError.invalidMessage("Truncated CDSI field") }
                let end = position + Int(count)
                if field == 1 { response.triples = Data(bytes[position..<end]) }
                if field == 3 { response.token = Data(bytes[position..<end]) }
                position = end
            default: throw SignalError.invalidMessage("Unsupported protobuf wire type")
            }
        }
        return response
    }
}
