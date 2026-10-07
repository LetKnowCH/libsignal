// SPDX-License-Identifier: AGPL-3.0-only
@testable import LibSignalClient
import XCTest

@available(iOS 15.0, macOS 12.0, *)
final class NitroTests: XCTestCase {
    private var resources: Bundle {
        #if SWIFT_PACKAGE
        return Bundle.module
        #else
        return Bundle(for: NitroTests.self)
        #endif
    }
    private func hex(_ text: String) -> Data {
        var result = Data()
        var index = text.startIndex
        while index < text.endIndex {
            let end = text.index(index, offsetBy: 2)
            result.append(UInt8(text[index..<end], radix: 16)!)
            index = end
        }
        return result
    }
    func testSignedAwsFixtureThroughSwiftBridge() throws {
        // Fixed historical time is for this signed fixture only. Live calls use Date().
        let metadata = try JSONSerialization.jsonObject(with: Data(contentsOf:
            resources.url(forResource: "cdsi_nitro_metadata", withExtension: "json")!
        )) as! [String: Any]
        let measurements = metadata["measurements"] as! [String: String]
        let policy = (0..<3).reduce(into: Data()) { $0.append(hex(measurements["PCR\($1)"]!)) }
        let challenge = hex(metadata["challenge"] as! String)
        let date = Date(timeIntervalSince1970: (metadata["verified_at_millis"] as! Double) / 1000)
        let evidence = try Data(contentsOf: resources.url(forResource: "cdsi_nitro_handshake", withExtension: "dat")!)
        let client = try NitroCds2Client(expectedPcrs: policy, challenge: challenge, attestationMessage: evidence, currentDate: date)
        XCTAssertFalse(client.initialRequest().isEmpty)
        var wrong = policy
        wrong[0] ^= 1
        XCTAssertThrowsError(try NitroCds2Client(expectedPcrs: wrong, challenge: challenge, attestationMessage: evidence, currentDate: date))
        XCTAssertThrowsError(try NitroCds2Client(expectedPcrs: policy, challenge: Data(repeating: 0, count: 32), attestationMessage: evidence, currentDate: date))
        XCTAssertThrowsError(try NitroCds2Client(expectedPcrs: policy, challenge: challenge, attestationMessage: evidence, currentDate: date.addingTimeInterval(301)))
        var altered = evidence
        altered[altered.count - 1] ^= 1
        XCTAssertThrowsError(try NitroCds2Client(expectedPcrs: policy, challenge: challenge, attestationMessage: altered, currentDate: date))
    }
    func testChallengeAndEndpointPolicy() throws {
        let first = try NitroCds2Client.makeChallenge()
        XCTAssertEqual(first.count, 32)
        XCTAssertNotEqual(first, try NitroCds2Client.makeChallenge())
        let policy = Data(repeating: 1, count: 144)
        XCTAssertThrowsError(try NitroContactDiscovery(endpoint: URL(string: "ws://example.com/v1/nitro/discovery")!, expectedPcrs: policy))
        XCTAssertThrowsError(try NitroContactDiscovery(endpoint: URL(string: "wss://example.com/v1/nitro/discovery")!, expectedPcrs: Data(repeating: 0, count: 144)))
    }
    func testProtobufBoundsAndDuplicateFields() throws {
        let encoded = NitroCdsiWire.bytes(3, Data(repeating: 7, count: 65))
        XCTAssertEqual(try NitroCdsiWire.decode(encoded).token.count, 65)
        for invalid in [Data([0]), Data([0x1a, 65, 1]), Data([0x20] + Array(repeating: 0xff, count: 10)), encoded + encoded] {
            XCTAssertThrowsError(try NitroCdsiWire.decode(invalid))
        }
    }
}
