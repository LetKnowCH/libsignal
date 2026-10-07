# CDSI Nitro fixture

`cdsi_nitro_handshake.dat` contains a real AWS-signed attestation message from the synthetic CDSI prototype.
`cdsi_nitro_metadata.json` contains its challenge, approved build measurements, and verification time.
The message was captured on 7 October 2026 in the stage account, on Nitro hardware with debug mode disabled.
It binds the prototype protocol context and its X25519 public key. It contains no private key or real contact data.

The integration test uses the recorded time so certificate expiry does not make the fixture test unstable.
The live client uses the current system time and a newly generated challenge for each connection.
The test does not install these measurements as a default client trust policy.

The source was `contact-discovery-service/nitro-prototype`, linked against the modified `attest` crate.
The successful live SSM command was `47f8fe11-4bd2-4c42-9e5a-ce749bbc8446`.
The host runner terminated the enclave after the encrypted lookup passed.

`nitro_legacy_signed.dat` is the existing historical AWS fixture from libsignal before commit `6c06d8361`.
It is retained for certificate and signature regression tests; it is not a CDSI protocol fixture.
