#![cfg(not(target_os = "solana"))]

use solana_bls_signatures::{
    proof_of_possession::ProofOfPossessionProjective,
    pubkey::{PubkeyAffine, PubkeyAffineUnchecked},
    signature::{SignatureAffine, SignatureAffineUnchecked, SignatureProjective},
    Keypair, ProofOfPossession, Pubkey, Signature,
};

#[test]
fn canonical_uncompressed_points_roundtrip() {
    let keypair = Keypair::derive(&[42; 32]).unwrap();

    // Include identity signatures to check that the infinity flag remains allowed.
    for point in [
        keypair.sign(b"uncompressed encoding"),
        SignatureProjective::identity(),
    ] {
        let bytes = Signature::from(point);
        assert_eq!(SignatureProjective::try_from(bytes).unwrap(), point);
        assert_eq!(
            SignatureAffineUnchecked::try_from(bytes)
                .unwrap()
                .verify_subgroup()
                .unwrap(),
            SignatureAffine::from(point),
        );
    }

    let pubkey = Pubkey::from(*keypair.public);
    assert_eq!(PubkeyAffine::try_from(pubkey).unwrap(), *keypair.public);
    assert_eq!(
        PubkeyAffineUnchecked::try_from(pubkey)
            .unwrap()
            .verify_subgroup()
            .unwrap(),
        *keypair.public,
    );

    let proof = keypair.proof_of_possession(None);
    let bytes = ProofOfPossession::from(proof);
    assert_eq!(ProofOfPossessionProjective::try_from(bytes).unwrap(), proof);
}

#[cfg(feature = "wincode")]
#[test]
fn wincode_preserves_raw_signature_bytes() {
    use solana_bls_signatures::{BlsError, BLS_SIGNATURE_AFFINE_SIZE};

    // Raw byte wrappers remain serializable; validation belongs to point conversion.
    let signature = Signature([0xFF; BLS_SIGNATURE_AFFINE_SIZE]);
    let bytes = wincode::serialize(&signature).unwrap();
    assert_eq!(bytes, signature.0);
    assert_eq!(
        wincode::deserialize::<Signature>(&bytes).unwrap(),
        signature
    );
    assert_eq!(
        SignatureAffine::try_from(signature),
        Err(BlsError::PointConversion),
    );
}
