//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

///
/// Svr2Client provides bindings to interact with Signal's v2 Secure Value Recovery service.
///
/// See ``SgxClient``
public class Svr2Client: SgxClient {
    /// Verifies the pinned LetKnow staging Nitro recovery enclave and its Raft group.
    public convenience init(letKnowNitroAttestation: Data, currentDate: Date) throws {
        let milliseconds = currentDate.timeIntervalSince1970 * 1000
        guard milliseconds.isFinite, milliseconds >= 0, milliseconds < Double(UInt64.max) else {
            throw SignalError.invalidArgument("Invalid recovery verification time")
        }
        let handle = try letKnowNitroAttestation.withUnsafeBorrowedBuffer { evidence in
            try invokeFnReturningValueByPointer(.init()) {
                signal_nitro_svr2_client_new($0, evidence, UInt64(milliseconds))
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    public convenience init(
        mrenclave: some ContiguousBytes,
        attestationMessage: some ContiguousBytes,
        currentDate: Date
    ) throws {
        let handle = try attestationMessage.withUnsafeBorrowedBuffer { attestationMessageBuffer in
            try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBuffer in
                try invokeFnReturningValueByPointer(.init()) {
                    signal_svr2_client_new(
                        $0,
                        mrenclaveBuffer,
                        attestationMessageBuffer,
                        UInt64(currentDate.timeIntervalSince1970 * 1000)
                    )
                }
            }
        }
        self.init(owned: NonNull(handle)!)
    }
}
