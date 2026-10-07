// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(feature = "nitro")]

use std::time::{Duration, SystemTime};

use attest::cds2::new_nitro_handshake;
use attest::nitro::{self, ExpectedPcrs};
use ciborium::value::Value;
use prost::Message;

const HANDSHAKE: &[u8] = include_bytes!("data/cdsi_nitro_handshake.dat");
#[derive(Clone, PartialEq, Message)]
struct Start {
    #[prost(bytes = "vec", tag = "2")]
    evidence: Vec<u8>,
}
fn inputs() -> (ExpectedPcrs, [u8; 32], SystemTime) {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("data/cdsi_nitro_metadata.json")).unwrap();
    let mut pcrs = [[0; 48]; 3];
    for (i, pcr) in pcrs.iter_mut().enumerate() {
        *pcr = hex::decode(data["measurements"][format!("PCR{i}")].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    }
    let nonce = hex::decode(data["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let now = SystemTime::UNIX_EPOCH
        + Duration::from_millis(data["verified_at_millis"].as_u64().unwrap());
    (ExpectedPcrs(pcrs), nonce, now)
}
#[test]
fn accepts_captured_real_nitro_evidence() {
    let (pcrs, nonce, now) = inputs();
    let handshake = new_nitro_handshake(&pcrs, &nonce, HANDSHAKE, now).unwrap();
    assert!(!handshake.initial_request().is_empty());
}
#[test]
fn rejects_replay_expiry_and_every_wrong_measurement() {
    let (pcrs, nonce, now) = inputs();
    for index in 0..3 {
        let mut wrong = pcrs.clone();
        wrong.0[index][0] ^= 1;
        assert!(new_nitro_handshake(&wrong, &nonce, HANDSHAKE, now).is_err());
        wrong.0[index] = [0; 48];
        assert!(new_nitro_handshake(&wrong, &nonce, HANDSHAKE, now).is_err());
    }
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    assert!(new_nitro_handshake(&pcrs, &wrong_nonce, HANDSHAKE, now).is_err());
    assert!(new_nitro_handshake(&pcrs, &nonce, HANDSHAKE, now + Duration::from_secs(301)).is_err());
    assert!(new_nitro_handshake(&pcrs, &nonce, HANDSHAKE, now - Duration::from_secs(60)).is_err());
}
#[test]
fn rejects_unsigned_replacement_key_and_endorsement() {
    let (pcrs, nonce, now) = inputs();
    for tag in [0x0a, 0x1a] {
        let mut replaced = HANDSHAKE.to_vec();
        replaced.extend_from_slice(&[tag, 32]);
        replaced.extend_from_slice(&[7; 32]);
        assert!(new_nitro_handshake(&pcrs, &nonce, &replaced, now).is_err());
    }
}
#[test]
fn rejects_replacement_key_inside_signed_payload() {
    let (pcrs, nonce, now) = inputs();
    let mut start = Start::decode(HANDSHAKE).unwrap();
    let mut cose: Value = ciborium::from_reader(start.evidence.as_slice()).unwrap();
    let untagged = match &mut cose {
        Value::Tag(18, value) => value.as_mut(),
        value => value,
    };
    let parts = untagged.as_array_mut().unwrap();
    let mut payload: Value =
        ciborium::from_reader(parts[2].as_bytes().unwrap().as_slice()).unwrap();
    let fields = payload.as_map_mut().unwrap();
    let (_, user_data) = fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("user_data"))
        .unwrap();
    let bytes = user_data.as_bytes_mut().unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).unwrap();
    parts[2] = Value::Bytes(encoded);
    start.evidence.clear();
    ciborium::into_writer(&cose, &mut start.evidence).unwrap();
    assert_eq!(
        nitro::verify(&start.evidence, &pcrs, &nonce, now),
        Err(nitro::Error::Signature)
    );
}
