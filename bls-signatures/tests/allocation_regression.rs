// Run: cargo test -p solana-bls-signatures --release --test allocation_regression
// Standalone Cargo test: register this target with harness = false.
// This keeps libtest activity out of the process-wide allocation counter.
// Counts successful Rust global-allocator requests through System, not C malloc.
// Reallocations are separate calls; their full new size contributes to bytes.
// BLS budgets are upper bounds: reductions pass; tighten after measuring them.

use {
    solana_bls_signatures::{
        error::BlsError,
        hash::{HashedMessage, PreparedHashedMessage},
        keypair::Keypair,
        pubkey::VerifySignature,
        signature::{SignatureAffine, SignatureCompressed, SignatureProjective},
    },
    std::{
        alloc::{GlobalAlloc, Layout, System},
        hint::black_box,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREED_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: Every request is forwarded unchanged to System. The bookkeeping
// uses only atomics: it does not allocate, dereference pointers, or unwind.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() && COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Forward the caller's valid allocation and resize request.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && COUNTING.load(Ordering::Relaxed) {
            REALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(new_size, Ordering::Relaxed);
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if COUNTING.load(Ordering::Relaxed) {
            DEALLOCS.fetch_add(1, Ordering::Relaxed);
            FREED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        // SAFETY: Allocations handled by this allocator come from System.
        unsafe { System.dealloc(ptr, layout) };
    }
}

const ITERATIONS: usize = 100;
const WARMUP: usize = 8;

// Allocation ceilings for blstrs 0.7.1 and blst 0.3.17.
// Keep the control allocation exact so a disabled counter cannot pass.
fn check_budget(
    label: &str,
    allocs: usize,
    bytes: usize,
    reallocs: usize,
    deallocs: usize,
    freed_bytes: usize,
) {
    let (max_allocs, max_bytes) = match label {
        "control/empty" | "hash_message" => (0, 0),
        "control/box64" => (1, 64),
        "prepare/from_hashed" | "prepare/from_raw" => (1, 19_584),
        name if name.starts_with("verify/prepared/") => (0, 0),
        name if name.starts_with("verify/raw/")
            || name.starts_with("verify/pre_hashed/")
            || name.starts_with("verify/raw_compressed/") =>
        {
            (0, 0)
        }
        name if name.starts_with("aggregate/raw/")
            || name.starts_with("aggregate/pre_hashed/") =>
        {
            (1, 19_584)
        }
        name if name.starts_with("aggregate/prepared/") => (0, 0),
        _ => panic!("missing allocation budget for {label}"),
    };

    assert_eq!(reallocs, 0, "unexpected reallocation in {label}");
    assert_eq!(
        deallocs, allocs,
        "unbalanced allocation/free calls in {label}"
    );
    assert_eq!(
        freed_bytes, bytes,
        "unbalanced allocated/freed bytes in {label}"
    );
    assert!(
        allocs <= max_allocs * ITERATIONS,
        "{label}: {allocs} allocations exceed the limit of {max_allocs} per operation",
    );
    assert!(
        bytes <= max_bytes * ITERATIONS,
        "{label}: {bytes} requested bytes exceed the limit of {max_bytes} per operation",
    );

    if label == "control/box64" {
        assert_eq!(allocs, ITERATIONS, "allocation counter control failed");
        assert_eq!(bytes, 64 * ITERATIONS, "byte counter control failed");
    }
}

fn measure(label: &str, mut operation: impl FnMut() -> bool) {
    for _ in 0..WARMUP {
        assert!(black_box(operation()), "unexpected result in {label}");
    }

    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    REALLOCS.store(0, Ordering::Relaxed);
    DEALLOCS.store(0, Ordering::Relaxed);
    FREED_BYTES.store(0, Ordering::Relaxed);

    let mut matching_results = 0usize;
    COUNTING.store(true, Ordering::SeqCst);
    for _ in 0..ITERATIONS {
        matching_results += usize::from(black_box(operation()));
    }
    COUNTING.store(false, Ordering::SeqCst);

    let allocs = ALLOCS.load(Ordering::Relaxed);
    let bytes = BYTES.load(Ordering::Relaxed);
    let reallocs = REALLOCS.load(Ordering::Relaxed);
    let deallocs = DEALLOCS.load(Ordering::Relaxed);
    let freed_bytes = FREED_BYTES.load(Ordering::Relaxed);

    assert_eq!(matching_results, ITERATIONS, "unexpected result in {label}");
    let n = ITERATIONS as f64;
    println!(
        "{label:<38} {:>10.2} {:>12.2} {:>10.2} {:>10.2}",
        allocs as f64 / n,
        bytes as f64 / n,
        reallocs as f64 / n,
        deallocs as f64 / n,
    );
    check_budget(label, allocs, bytes, reallocs, deallocs, freed_bytes);
}

fn main() {
    // All fixture creation happens while counting is disabled.
    let keypair = Keypair::derive(&[42u8; 32]).expect("derive fixture key");
    let message: &[u8] = b"solana-bls-signatures allocation baseline";
    let valid: SignatureCompressed = keypair.sign(message).into();
    let wrong: SignatureCompressed = keypair.sign(b"a different message").into();
    let hashed = HashedMessage::new(message);
    let prepared = PreparedHashedMessage::from_hashed_message(&hashed);

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

    println!("allocation regression v1; {ITERATIONS} operations per row; 3 passes");
    println!("parallel feature enabled: {}", cfg!(feature = "parallel"));
    println!("raw/pre_hashed/prepared use affine keys and affine signatures.");
    println!("raw_compressed also decodes the compressed signature each time.");
    println!("Counts include destruction of temporaries within each operation.");
    println!("aggregate rows include aggregation of two affine keys and signatures.");

    for pass in 1..=3 {
        println!("\npass {pass}");
        println!(
            "{:<38} {:>10} {:>12} {:>10} {:>10}",
            "operation", "alloc/op", "bytes/op", "realloc/op", "free/op",
        );

        measure("control/empty", || black_box(true));
        measure("control/box64", || {
            drop(black_box(Box::new(black_box([0u8; 64]))));
            true
        });
        measure("hash_message", || {
            black_box(HashedMessage::new(black_box(message)));
            true
        });
        measure("prepare/from_hashed", || {
            drop(black_box(PreparedHashedMessage::from_hashed_message(
                black_box(&hashed),
            )));
            true
        });
        measure("prepare/from_raw", || {
            drop(black_box(PreparedHashedMessage::new(black_box(message))));
            true
        });

        for (status, encoded, expected) in [
            ("valid", &valid, Ok(())),
            ("wrong_message", &wrong, Err(BlsError::VerificationFailed)),
        ] {
            // Both encodings must decode successfully. The second signature
            // is a valid group point, signed for a different message.
            let affine = SignatureAffine::try_from(encoded).expect("decode fixture signature");

            measure(&format!("verify/raw/{status}"), || {
                black_box(&keypair.public).verify_signature(black_box(&affine), black_box(message))
                    == expected
            });
            measure(&format!("verify/pre_hashed/{status}"), || {
                black_box(&keypair.public)
                    .verify_signature_pre_hashed(black_box(&affine), black_box(&hashed))
                    == expected
            });
            measure(&format!("verify/prepared/{status}"), || {
                black_box(&keypair.public)
                    .verify_signature_prepared(black_box(&affine), black_box(&prepared))
                    == expected
            });
            measure(&format!("verify/raw_compressed/{status}"), || {
                black_box(&keypair.public).verify_signature(black_box(encoded), black_box(message))
                    == expected
            });
        }

        for (status, signatures, expected) in [
            ("valid", &aggregate_valid, Ok(())),
            (
                "wrong_message",
                &aggregate_wrong,
                Err(BlsError::VerificationFailed),
            ),
        ] {
            measure(&format!("aggregate/raw/{status}"), || {
                SignatureProjective::verify_aggregate(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(message),
                ) == expected
            });
            measure(&format!("aggregate/pre_hashed/{status}"), || {
                SignatureProjective::verify_aggregate_pre_hashed(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(&hashed),
                ) == expected
            });
            measure(&format!("aggregate/prepared/{status}"), || {
                SignatureProjective::verify_aggregate_prepared(
                    black_box(&aggregate_pubkeys).iter(),
                    black_box(signatures).iter(),
                    black_box(&prepared),
                ) == expected
            });
        }
    }

    println!("\nAllocation budgets and verification outcomes passed.");
}
