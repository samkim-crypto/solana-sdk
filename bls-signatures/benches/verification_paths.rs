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
        signature::{SignatureAffine, SignatureCompressed, SignatureProjective},
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

    // Match the allocation test: aggregate two affine keys and signatures
    // inside each timed operation. Message preparation stays outside the
    // timed loop for the prepared path.
    let other_keypair = Keypair::derive(&[43u8; 32]).expect("derive second aggregate key");
    let aggregate_pubkeys = [keypair.public, other_keypair.public];
    let other_signature: SignatureAffine = other_keypair.sign(message).into();
    let aggregate_valid = [
        SignatureAffine::try_from(&valid).expect("decode first aggregate signature"),
        other_signature,
    ];
    let aggregate_wrong = [
        SignatureAffine::try_from(&wrong).expect("decode wrong-message aggregate signature"),
        other_signature,
    ];

    let mut aggregate = c.benchmark_group("bls_aggregate");
    for (status, signatures, expected) in [
        ("valid", &aggregate_valid, Ok(())),
        (
            "wrong_message",
            &aggregate_wrong,
            Err(BlsError::VerificationFailed),
        ),
    ] {
        assert_eq!(
            SignatureProjective::verify_aggregate(
                aggregate_pubkeys.iter(),
                signatures.iter(),
                message,
            ),
            expected,
            "aggregate/raw/{status}",
        );
        assert_eq!(
            SignatureProjective::verify_aggregate_pre_hashed(
                aggregate_pubkeys.iter(),
                signatures.iter(),
                &hashed,
            ),
            expected,
            "aggregate/pre_hashed/{status}",
        );
        assert_eq!(
            SignatureProjective::verify_aggregate_prepared(
                aggregate_pubkeys.iter(),
                signatures.iter(),
                &prepared,
            ),
            expected,
            "aggregate/prepared/{status}",
        );

        aggregate.bench_function(format!("raw/{status}"), |b| {
            b.iter(|| {
                black_box(SignatureProjective::verify_aggregate(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(message),
                ))
            });
        });
        aggregate.bench_function(format!("pre_hashed/{status}"), |b| {
            b.iter(|| {
                black_box(SignatureProjective::verify_aggregate_pre_hashed(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(&hashed),
                ))
            });
        });
        aggregate.bench_function(format!("prepared/{status}"), |b| {
            b.iter(|| {
                black_box(SignatureProjective::verify_aggregate_prepared(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(&prepared),
                ))
            });
        });
    }
    aggregate.finish();
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

