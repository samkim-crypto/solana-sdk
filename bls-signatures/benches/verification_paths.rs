// Run with the verification_paths Cargo bench target (harness = false).
// Preparation benchmarks include destruction of the temporary preparation.
// Prepared verification reuses a preparation created outside the timed loop.

use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bls_signatures::{
        error::BlsError,
        hash::{HashedMessage, PreparedHashedMessage},
        keypair::Keypair,
        pubkey::VerifySignature,
        signature::{SignatureAffine, SignatureCompressed},
    },
    std::{hint::black_box, time::Duration},
};

fn verification_paths(c: &mut Criterion) {
    // Use the same fixtures as the allocation regression test.
    let keypair = Keypair::derive(&[42u8; 32]).expect("derive fixture key");
    let message: &[u8] = b"solana-bls-signatures allocation baseline";
    let valid: SignatureCompressed = keypair.sign(message).into();
    let wrong: SignatureCompressed = keypair.sign(b"a different message").into();
    let hashed = HashedMessage::new(message);
    let prepared = PreparedHashedMessage::from_hashed_message(&hashed);

    let mut setup = c.benchmark_group("bls_setup");
    setup.bench_function("hash_message", |b| {
        b.iter(|| black_box(HashedMessage::new(black_box(message))));
    });
    setup.bench_function("prepare_from_hashed", |b| {
        b.iter(|| {
            drop(black_box(PreparedHashedMessage::from_hashed_message(
                black_box(&hashed),
            )));
        });
    });
    setup.bench_function("prepare_from_raw", |b| {
        b.iter(|| {
            drop(black_box(PreparedHashedMessage::new(black_box(message))));
        });
    });
    setup.finish();

    let mut verify = c.benchmark_group("bls_verify");
    for (status, encoded, expected) in [
        ("valid", &valid, Ok(())),
        ("wrong_message", &wrong, Err(BlsError::VerificationFailed)),
    ] {
        let affine = SignatureAffine::try_from(encoded).expect("decode fixture signature");

        // Validate all four paths before timing them. The wrong-message
        // signature is correctly encoded and belongs to the prime-order group.
        assert_eq!(
            keypair.public.verify_signature(&affine, message),
            expected,
            "raw/{status}",
        );
        assert_eq!(
            keypair.public.verify_signature_pre_hashed(&affine, &hashed),
            expected,
            "pre_hashed/{status}",
        );
        assert_eq!(
            keypair.public.verify_signature_prepared(&affine, &prepared),
            expected,
            "prepared/{status}",
        );
        assert_eq!(
            keypair.public.verify_signature(encoded, message),
            expected,
            "raw_compressed/{status}",
        );

        verify.bench_function(format!("raw/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature(black_box(&affine), black_box(message)),
                )
            });
        });
        verify.bench_function(format!("pre_hashed/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature_pre_hashed(black_box(&affine), black_box(&hashed)),
                )
            });
        });
        verify.bench_function(format!("prepared/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature_prepared(black_box(&affine), black_box(&prepared)),
                )
            });
        });
        verify.bench_function(format!("raw_compressed/{status}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&keypair.public)
                        .verify_signature(black_box(encoded), black_box(message)),
                )
            });
        });
    }
    verify.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100);
    targets = verification_paths
}
criterion_main!(benches);

