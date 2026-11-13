//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use prost::Message;

use crate::dcap;
use crate::enclave::{Handshake, HandshakeType, Result};
use crate::proto::cds2;
use crate::util::get_sw_advisories;

pub fn new_handshake(
    mrenclave: &[u8],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Handshake> {
    // Deserialize attestation handshake start.
    let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    Ok(Handshake::for_sgx(
        mrenclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        get_sw_advisories(mrenclave),
        current_time,
        HandshakeType::PostQuantum,
    )?
    .skip_raft_validation())
}

/// Extracts attestation metrics from a `ClientHandshakeStart` message
pub fn extract_metrics(attestation_msg: &[u8]) -> Result<HashMap<String, i64>> {
    let handshake_start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    Ok(dcap::attestation_metrics(
        &handshake_start.evidence,
        &handshake_start.endorsement,
    )?)
}

/// Starts an experimental CDSI Nitro session using a caller-owned measurement policy.
/// The caller must generate a fresh challenge and send it before receiving evidence.
/// Never construct `expected` from measurements supplied by the remote endpoint.
#[cfg(feature = "nitro")]
pub fn new_nitro_handshake(
    expected: &crate::nitro::ExpectedPcrs,
    challenge: &[u8; 32],
    attestation_msg: &[u8],
    current_time: std::time::SystemTime,
) -> Result<Handshake> {
    use crate::enclave::{Claims, Error};
    let invalid = |reason: &str| Error::AttestationDataError {
        reason: reason.into(),
    };
    if attestation_msg.len() > crate::nitro::MAX_DOCUMENT_SIZE + 64 {
        return Err(invalid("Nitro handshake exceeds size limit"));
    }
    let start = cds2::ClientHandshakeStart::decode(attestation_msg)?;
    if !start.pubkey.is_empty() || !start.endorsement.is_empty() {
        return Err(invalid("unexpected fields in Nitro handshake"));
    }
    let public_key = crate::nitro::verify(&start.evidence, expected, challenge, current_time)
        .map_err(|e| invalid(&e.to_string()))?;
    let claims = Claims::from_custom_claims(HashMap::from([("pk".into(), public_key.to_vec())]))?;
    Ok(Handshake::with_claims(claims, HandshakeType::PostQuantum)?.skip_raft_validation())
}

#[cfg(test)]
mod test {
    use std::time::{Duration, SystemTime};

    use const_str::hex;

    use super::*;

    #[test]
    fn attest_cds2() {
        // Read test data files, de-hex-stringing as necessary.
        let mrenclave = hex!("39d78f17f8aa9a8e9cdaf16595947a057bac21f014d1abfd6a99b2dfd4e18d1d");

        let attestation_msg = cds2::ClientHandshakeStart {
            evidence: include_bytes!("../tests/data/cds2_test.evidence").to_vec(),
            endorsement: include_bytes!("../tests/data/cds2_test.endorsements").to_vec(),
            ..Default::default()
        };

        let current_time = SystemTime::UNIX_EPOCH + Duration::from_millis(1655857680000);

        assert!(new_handshake(&mrenclave, &attestation_msg.encode_to_vec(), current_time).is_ok());
    }
}
