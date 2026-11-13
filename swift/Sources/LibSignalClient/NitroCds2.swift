// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import Security
import SignalFfi

/// Verifies an AWS Nitro CDSI session and provides its encrypted Noise channel.
/// Obtain PCRs from a trusted release manifest, never from the remote service.
/// The inherited native handle stores the Noise state for both enclave types.
public final class NitroCds2Client: SgxClient {
    /// Generate one fresh challenge for each connection, before receiving evidence.
    public static func makeChallenge() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw SignalError.internalError("Could not generate Nitro challenge")
        }
        return Data(bytes)
    }

    /// Validates the evidence before it creates a Noise client.
    /// `expectedPcrs` contains PCR0, PCR1 and PCR2, each exactly 48 bytes.
    public convenience init(
        expectedPcrs: Data,
        challenge: Data,
        attestationMessage: Data,
        currentDate: Date = Date()
    ) throws {
        let milliseconds = currentDate.timeIntervalSince1970 * 1000
        guard milliseconds.isFinite, milliseconds >= 0, milliseconds < Double(UInt64.max) else {
            throw SignalError.invalidArgument("Invalid attestation verification time")
        }
        let handle = try expectedPcrs.withUnsafeBorrowedBuffer { pcrBuffer in
            try challenge.withUnsafeBorrowedBuffer { challengeBuffer in
                try attestationMessage.withUnsafeBorrowedBuffer { evidenceBuffer in
                    try invokeFnReturningValueByPointer(.init()) {
                        signal_nitro_cds2_client_state_new(
                            $0, pcrBuffer, challengeBuffer, evidenceBuffer, UInt64(milliseconds)
                        )
                    }
                }
            }
        }
        self.init(owned: NonNull(handle)!)
    }
}
