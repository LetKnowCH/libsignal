//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::enclave::Result;
use ::attest::svr2;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::sgx_session::SgxClientState;

use crate::protocol::Timestamp;
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

#[bridge_fn]
fn Svr2Client_New(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<SgxClientState> {
    SgxClientState::new(svr2::new_handshake_with_raft_config_lookup(
        mrenclave,
        attestation_msg,
        current_timestamp.into(),
    )?)
}

// Pinned staging release: infrastructure/experiments/recovery-service/client-policy.json.
#[cfg(feature = "ffi")]
pub(crate) const NITRO_PIN_GROUP: u64 = 12467393807089275004;

#[cfg(feature = "ffi")]
#[bridge_fn(jni = false, node = false)]
fn NitroSvr2Client_New(
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<SgxClientState> {
    let pcrs = ::attest::nitro::ExpectedPcrs([
        [
            110, 50, 58, 96, 191, 183, 212, 170, 160, 26, 251, 40, 253, 28, 107, 226, 205, 73, 242,
            222, 244, 195, 80, 75, 231, 215, 149, 106, 199, 183, 254, 22, 23, 15, 183, 183, 162,
            84, 164, 123, 214, 59, 224, 57, 240, 118, 157, 194,
        ],
        [
            75, 77, 91, 54, 97, 179, 239, 193, 41, 32, 144, 12, 128, 225, 38, 228, 206, 120, 60,
            82, 45, 230, 192, 42, 42, 91, 247, 175, 58, 43, 147, 39, 184, 103, 118, 241, 136, 228,
            190, 28, 28, 64, 74, 18, 157, 189, 164, 147,
        ],
        [
            53, 0, 244, 49, 76, 122, 118, 192, 25, 179, 25, 82, 102, 117, 8, 59, 246, 215, 26, 202,
            164, 190, 1, 107, 170, 165, 164, 125, 58, 128, 59, 189, 42, 135, 114, 162, 59, 238, 22,
            180, 139, 0, 16, 189, 179, 92, 70, 31,
        ],
    ]);
    let policy = svr2::RaftConfig {
        group_id: NITRO_PIN_GROUP,
        min_voting_replicas: 3,
        max_voting_replicas: 9,
        super_majority: 0,
        db_version: 2,
        attestation_timeout: 3600,
        simulated: false,
    };
    SgxClientState::new(svr2::new_nitro_handshake(
        &pcrs,
        attestation_msg,
        current_timestamp.into(),
        &policy,
    )?)
}
