// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
// Adapted for the experimental LetKnow CDSI protocol from libsignal's former Nitro verifier.

//! AWS Nitro attestation verification for the synthetic CDSI prototype.
//! Trust comes from the pinned AWS root and caller-owned PCRs, never from the peer.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{Duration, SystemTime};

use boring_signal::bn::BigNum;
use boring_signal::ecdsa::EcdsaSig;
use boring_signal::nid::Nid;
use boring_signal::stack::Stack;
use boring_signal::x509::store::X509StoreBuilder;
use boring_signal::x509::{X509, X509StoreContext};
use ciborium::value::Value;
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;

pub const MAX_DOCUMENT_SIZE: usize = 16 * 1024;
pub const KEY_BINDING_CONTEXT: &[u8] = b"letknow-cdsi-nitro-v1\0";
const MAX_AGE: Duration = Duration::from_secs(300);
const CLOCK_SKEW: Duration = Duration::from_secs(30);
const ROOT: &[u8] = include_bytes!("../res/nitro_root_certificate.pem");

/// Exact approved PCR0, PCR1, and PCR2, in that order. Zero values are forbidden.
#[derive(Clone, Debug)]
pub struct ExpectedPcrs(pub [[u8; 48]; 3]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid or oversized CBOR")]
    Cbor,
    #[error("invalid COSE Sign1 envelope")]
    Cose,
    #[error("invalid attestation document")]
    Document,
    #[error("invalid AWS certificate chain")]
    Certificate,
    #[error("invalid attestation signature")]
    Signature,
    #[error("missing, debug, or unexpected PCR measurement")]
    Measurements,
    #[error("stale attestation or invalid verification time")]
    Time,
    #[error("attestation challenge does not match")]
    Challenge,
    #[error("invalid protocol or session key binding")]
    KeyBinding,
}

/// Verifies the AWS chain, signature, freshness, challenge, PCRs, and session key binding.
/// Returns the authenticated X25519 public key for the subsequent Noise handshake.
pub fn verify(
    evidence: &[u8],
    expected: &ExpectedPcrs,
    challenge: &[u8; 32],
    now: SystemTime,
) -> Result<[u8; 32], Error> {
    let envelope = Envelope::parse(evidence)?;
    let document = Document::parse(&envelope.payload)?;
    envelope.verify_signature(&document, now)?;
    document.verify_claims(expected, challenge, now)
}

fn decode(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_SIZE {
        return Err(Error::Cbor);
    }
    let mut cursor = Cursor::new(bytes);
    let value =
        ciborium::de::from_reader_with_recursion_limit(&mut cursor, 16).map_err(|_| Error::Cbor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Cbor);
    }
    Ok(value)
}

fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    ciborium::into_writer(value, &mut output).map_err(|_| Error::Cbor)?;
    Ok(output)
}

struct Envelope {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl Envelope {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let value = match decode(bytes)? {
            Value::Tag(18, inner) => *inner,
            value => value,
        };
        let parts: [Value; 4] = value
            .into_array()
            .map_err(|_| Error::Cose)?
            .try_into()
            .map_err(|_| Error::Cose)?;
        let [
            Value::Bytes(protected),
            Value::Map(unprotected),
            Value::Bytes(payload),
            Value::Bytes(signature),
        ] = parts
        else {
            return Err(Error::Cose);
        };
        if !unprotected.is_empty() || signature.len() != 96 || payload.is_empty() {
            return Err(Error::Cose);
        }
        let header = decode(&protected)?;
        if header
            != Value::Map(vec![(
                Value::Integer(1.into()),
                Value::Integer((-35).into()),
            )])
        {
            return Err(Error::Cose);
        }
        Ok(Self {
            protected,
            payload,
            signature,
        })
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(self.protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(self.payload.clone()),
        ]))
    }

    fn verify_signature(&self, document: &Document, now: SystemTime) -> Result<(), Error> {
        let certificate = document.verified_certificate(now)?;
        let key = certificate
            .public_key()
            .and_then(|k| k.ec_key())
            .map_err(|_| Error::Certificate)?;
        if key.group().curve_name() != Some(Nid::SECP384R1) {
            return Err(Error::Certificate);
        }
        // parse() checked the exact signature length before either slice is used.
        let r = BigNum::from_slice(&self.signature[..48]).map_err(|_| Error::Signature)?;
        let s = BigNum::from_slice(&self.signature[48..]).map_err(|_| Error::Signature)?;
        let signature = EcdsaSig::from_private_components(r, s).map_err(|_| Error::Signature)?;
        let digest = Sha384::digest(self.signing_bytes()?);
        if !signature
            .verify(&digest, &key)
            .map_err(|_| Error::Signature)?
        {
            return Err(Error::Signature);
        }
        Ok(())
    }
}

struct Document {
    timestamp: u64,
    pcrs: BTreeMap<usize, [u8; 48]>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    user_data: Vec<u8>,
    nonce: Vec<u8>,
    public_key: Vec<u8>,
}

impl Document {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let entries = decode(bytes)?.into_map().map_err(|_| Error::Document)?;
        let mut fields = BTreeMap::new();
        for (key, value) in entries {
            let key = key.into_text().map_err(|_| Error::Document)?;
            if fields.insert(key, value).is_some() {
                return Err(Error::Document);
            }
        }
        let module = take(&mut fields, "module_id")?
            .into_text()
            .map_err(|_| Error::Document)?;
        if module.is_empty()
            || module.len() > 256
            || take(&mut fields, "digest")? != Value::Text("SHA384".into())
        {
            return Err(Error::Document);
        }
        let timestamp = take(&mut fields, "timestamp")?
            .into_integer()
            .map_err(|_| Error::Document)?;
        let timestamp = u64::try_from(timestamp).map_err(|_| Error::Document)?;
        if timestamp == 0 {
            return Err(Error::Document);
        }
        let pairs = take(&mut fields, "pcrs")?
            .into_map()
            .map_err(|_| Error::Document)?;
        if pairs.is_empty() || pairs.len() > 32 {
            return Err(Error::Document);
        }
        let mut pcrs = BTreeMap::new();
        for (index, value) in pairs {
            let index = index.into_integer().map_err(|_| Error::Document)?;
            let index = usize::try_from(index).map_err(|_| Error::Document)?;
            let pcr: [u8; 48] = value
                .into_bytes()
                .map_err(|_| Error::Document)?
                .try_into()
                .map_err(|_| Error::Document)?;
            if index >= 32 || pcrs.insert(index, pcr).is_some() {
                return Err(Error::Document);
            }
        }
        let certificate = certificate_bytes(take(&mut fields, "certificate")?)?;
        let bundle = take(&mut fields, "cabundle")?
            .into_array()
            .map_err(|_| Error::Document)?;
        if bundle.is_empty() || bundle.len() > 8 {
            return Err(Error::Document);
        }
        let cabundle = bundle
            .into_iter()
            .map(certificate_bytes)
            .collect::<Result<_, _>>()?;
        let user_data = optional_bytes(fields.remove("user_data"))?;
        let nonce = optional_bytes(fields.remove("nonce"))?;
        // This protocol binds its raw session key in user_data, not in public_key.
        let public_key = optional_bytes(fields.remove("public_key"))?;
        if !fields.is_empty() {
            return Err(Error::Document);
        }
        Ok(Self {
            timestamp,
            pcrs,
            certificate,
            cabundle,
            user_data,
            nonce,
            public_key,
        })
    }

    fn verified_certificate(&self, now: SystemTime) -> Result<X509, Error> {
        let seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::Time)?
            .as_secs();
        let seconds = seconds.try_into().map_err(|_| Error::Time)?;
        let check = || -> Result<X509, boring_signal::error::ErrorStack> {
            let leaf = X509::from_der(&self.certificate)?;
            let mut chain = Stack::new()?;
            for der in &self.cabundle {
                chain.push(X509::from_der(der)?)?;
            }
            let mut trust = X509StoreBuilder::new()?;
            trust.param_mut().set_time(seconds);
            trust.add_cert(X509::from_pem(ROOT)?)?;
            let mut context = X509StoreContext::new()?;
            let valid = context.init(&trust.build(), &leaf, &chain, |ctx| ctx.verify_cert())?;
            if !valid {
                return Err(boring_signal::error::ErrorStack::get());
            }
            Ok(leaf)
        };
        check().map_err(|_| Error::Certificate)
    }

    fn verify_claims(
        &self,
        expected: &ExpectedPcrs,
        challenge: &[u8; 32],
        now: SystemTime,
    ) -> Result<[u8; 32], Error> {
        if !self.public_key.is_empty() {
            return Err(Error::KeyBinding);
        }
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::Time)?;
        let issued = Duration::from_millis(self.timestamp);
        if issued > now.saturating_add(CLOCK_SKEW) || now.saturating_sub(issued) > MAX_AGE {
            return Err(Error::Time);
        }
        if !bool::from(self.nonce.as_slice().ct_eq(challenge)) {
            return Err(Error::Challenge);
        }
        for (index, expected) in expected.0.iter().enumerate() {
            let actual = self.pcrs.get(&index).ok_or(Error::Measurements)?;
            if expected.iter().all(|b| *b == 0) || !bool::from(actual.ct_eq(expected)) {
                return Err(Error::Measurements);
            }
        }
        let key = self
            .user_data
            .strip_prefix(KEY_BINDING_CONTEXT)
            .ok_or(Error::KeyBinding)?;
        let key: [u8; 32] = key.try_into().map_err(|_| Error::KeyBinding)?;
        if key == [0; 32] {
            return Err(Error::KeyBinding);
        }
        Ok(key)
    }
}

fn take(fields: &mut BTreeMap<String, Value>, name: &str) -> Result<Value, Error> {
    fields.remove(name).ok_or(Error::Document)
}

fn certificate_bytes(value: Value) -> Result<Vec<u8>, Error> {
    let bytes = value.into_bytes().map_err(|_| Error::Document)?;
    if !(1..=1024).contains(&bytes.len()) {
        return Err(Error::Document);
    }
    Ok(bytes)
}

fn optional_bytes(value: Option<Value>) -> Result<Vec<u8>, Error> {
    match value {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Bytes(bytes)) if bytes.len() <= 1024 => Ok(bytes),
        _ => Err(Error::Document),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SIGNED: &[u8] = include_bytes!("../tests/data/nitro_legacy_signed.dat");

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1684362463)
    }
    fn claims() -> Document {
        Document {
            timestamp: 1684362463000,
            pcrs: BTreeMap::from([(0, [1; 48]), (1, [2; 48]), (2, [3; 48])]),
            certificate: vec![],
            cabundle: vec![],
            public_key: vec![],
            user_data: [KEY_BINDING_CONTEXT, &[4; 32]].concat(),
            nonce: vec![5; 32],
        }
    }
    fn expected() -> ExpectedPcrs {
        ExpectedPcrs([[1; 48], [2; 48], [3; 48]])
    }

    #[test]
    fn verifies_historical_aws_signature() {
        let envelope = Envelope::parse(SIGNED).unwrap();
        let document = Document::parse(&envelope.payload).unwrap();
        envelope.verify_signature(&document, now()).unwrap();
    }
    #[test]
    fn rejects_expired_or_untrusted_certificate() {
        let envelope = Envelope::parse(SIGNED).unwrap();
        let mut document = Document::parse(&envelope.payload).unwrap();
        assert_eq!(
            envelope.verify_signature(&document, SystemTime::UNIX_EPOCH),
            Err(Error::Certificate)
        );
        assert_eq!(
            envelope.verify_signature(&document, now() + Duration::from_secs(86400 * 365)),
            Err(Error::Certificate)
        );
        document.certificate = X509::from_pem(ROOT).unwrap().to_der().unwrap();
        assert!(envelope.verify_signature(&document, now()).is_err());
    }
    #[test]
    fn rejects_changed_signature_or_payload() {
        let mut envelope = Envelope::parse(SIGNED).unwrap();
        let document = Document::parse(&envelope.payload).unwrap();
        envelope.signature[0] ^= 1;
        assert_eq!(
            envelope.verify_signature(&document, now()),
            Err(Error::Signature)
        );
        envelope.signature[0] ^= 1;
        envelope.payload[0] ^= 1;
        assert_eq!(
            envelope.verify_signature(&document, now()),
            Err(Error::Signature)
        );
    }
    #[test]
    fn binds_key_protocol_challenge_and_measurements() {
        assert_eq!(
            claims().verify_claims(&expected(), &[5; 32], now()),
            Ok([4; 32])
        );
        let mut document = claims();
        document.user_data[0] ^= 1;
        assert_eq!(
            document.verify_claims(&expected(), &[5; 32], now()),
            Err(Error::KeyBinding)
        );
        document = claims();
        document.user_data.pop();
        assert_eq!(
            document.verify_claims(&expected(), &[5; 32], now()),
            Err(Error::KeyBinding)
        );
        document = claims();
        document.user_data = [KEY_BINDING_CONTEXT, &[0; 32]].concat();
        assert_eq!(
            document.verify_claims(&expected(), &[5; 32], now()),
            Err(Error::KeyBinding)
        );
        assert_eq!(
            claims().verify_claims(&expected(), &[6; 32], now()),
            Err(Error::Challenge)
        );
        for index in 0..3 {
            let mut document = claims();
            document.pcrs.remove(&index);
            assert_eq!(
                document.verify_claims(&expected(), &[5; 32], now()),
                Err(Error::Measurements)
            );
            document.pcrs.insert(index, [0; 48]);
            assert_eq!(
                document.verify_claims(&expected(), &[5; 32], now()),
                Err(Error::Measurements)
            );
            let mut policy = expected();
            policy.0[index] = [0; 48];
            assert_eq!(
                document.verify_claims(&policy, &[5; 32], now()),
                Err(Error::Measurements)
            );
        }
    }
    #[test]
    fn rejects_stale_and_future_documents() {
        assert_eq!(
            claims().verify_claims(&expected(), &[5; 32], now() + Duration::from_secs(301)),
            Err(Error::Time)
        );
        assert_eq!(
            claims().verify_claims(&expected(), &[5; 32], now() - Duration::from_secs(31)),
            Err(Error::Time)
        );
        assert_eq!(
            claims().verify_claims(
                &expected(),
                &[5; 32],
                SystemTime::UNIX_EPOCH - Duration::from_secs(1)
            ),
            Err(Error::Time)
        );
    }
    #[test]
    fn malformed_envelopes_never_panic() {
        for length in 0..SIGNED.len() {
            assert!(Envelope::parse(&SIGNED[..length]).is_err());
        }
        for major in [0x5b, 0x7b, 0x9b, 0xbb] {
            let mut huge = vec![major];
            huge.extend_from_slice(&u64::MAX.to_be_bytes());
            assert!(decode(&huge).is_err());
        }
        let mut trailing = SIGNED.to_vec();
        trailing.push(0);
        assert!(Envelope::parse(&trailing).is_err());
        assert!(Envelope::parse(&vec![0; MAX_DOCUMENT_SIZE + 1]).is_err());
        let mut deep = vec![0x81; 64];
        deep.push(0);
        assert!(decode(&deep).is_err());
        let value = decode(SIGNED).unwrap();
        let array = value.into_array().unwrap();
        for replacement in [Value::Bytes(vec![0xff]), Value::Bytes(vec![])] {
            let mut array = array.clone();
            array[0] = replacement;
            assert!(Envelope::parse(&encode(&Value::Array(array)).unwrap()).is_err());
        }
        let mut array = array.clone();
        array[3] = Value::Bytes(vec![0; 95]);
        assert!(Envelope::parse(&encode(&Value::Array(array)).unwrap()).is_err());
        assert!(
            Envelope::parse(&encode(&Value::Tag(17, Box::new(value_from_signed()))).unwrap())
                .is_err()
        );
        assert!(
            Envelope::parse(&encode(&Value::Tag(18, Box::new(value_from_signed()))).unwrap())
                .is_ok()
        );
    }
    fn value_from_signed() -> Value {
        decode(SIGNED).unwrap()
    }
    #[test]
    fn rejects_duplicate_fields_and_registers() {
        let envelope = Envelope::parse(SIGNED).unwrap();
        let entries = decode(&envelope.payload).unwrap().into_map().unwrap();
        let mut duplicate = entries.clone();
        duplicate.push(entries[0].clone());
        assert!(Document::parse(&encode(&Value::Map(duplicate)).unwrap()).is_err());
        let mut entries = entries;
        let (_, pcrs) = entries
            .iter_mut()
            .find(|(k, _)| *k == Value::Text("pcrs".into()))
            .unwrap();
        let pairs = pcrs.as_map_mut().unwrap();
        pairs.push(pairs[0].clone());
        assert!(Document::parse(&encode(&Value::Map(entries)).unwrap()).is_err());
    }
}
