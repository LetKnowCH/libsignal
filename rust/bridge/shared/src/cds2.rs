//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::attest::cds2;
use ::attest::enclave::Result;
use libsignal_bridge_macros::*;
#[cfg(all(not(target_os = "android"), feature = "jni"))]
use libsignal_bridge_types::cds2::Cds2Metrics;
use libsignal_bridge_types::sgx_session::SgxClientState;
use libsignal_bridge_types::support::*;

use crate::protocol::Timestamp;
use crate::*;

/// Builds an SGX client for the cds2 service
fn new_client(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<SgxClientState> {
    SgxClientState::new(cds2::new_handshake(
        mrenclave,
        attestation_msg,
        current_time,
    )?)
}

#[bridge_fn]
fn Cds2ClientState_New(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<SgxClientState> {
    new_client(
        mrenclave,
        attestation_msg,
        std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_millis(current_timestamp.epoch_millis()),
    )
}

#[cfg(not(target_os = "android"))]
#[bridge_fn(ffi = false, node = false)]
fn Cds2Metrics_extract(attestation_msg: &[u8]) -> Result<Cds2Metrics> {
    cds2::extract_metrics(attestation_msg).map(Cds2Metrics)
}

/// Builds a Nitro client with PCR0, PCR1 and PCR2 from a trusted release manifest.
/// Measurements are concatenated in that order. The challenge is fresh per connection.
#[cfg(feature = "ffi")]
#[bridge_fn(jni = false, node = false)]
fn NitroCds2ClientState_New(
    expected_pcrs: &[u8],
    challenge: &[u8],
    attestation_msg: &[u8],
    current_timestamp: Timestamp,
) -> Result<SgxClientState> {
    let invalid = || ::attest::enclave::Error::AttestationDataError {
        reason: "expected three 48-byte PCRs and a 32-byte challenge".into(),
    };
    let challenge = challenge.try_into().map_err(|_| invalid())?;
    let bytes: &[u8; 144] = expected_pcrs.try_into().map_err(|_| invalid())?;
    let mut pcrs = [[0u8; 48]; 3];
    for (pcr, source) in pcrs.iter_mut().zip(bytes.chunks_exact(48)) {
        pcr.copy_from_slice(source);
    }
    SgxClientState::new(cds2::new_nitro_handshake(
        &::attest::nitro::ExpectedPcrs(pcrs),
        challenge,
        attestation_msg,
        std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_millis(current_timestamp.epoch_millis()),
    )?)
}
