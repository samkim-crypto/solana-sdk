//! Aggregate screening for distinct-message signature sets.
//!
//! # Security Note: Individual Signature Validity
//!
//! The functions in this module perform aggregate screening by grouping signatures by message hash
//! and checking the aggregate relation per bucket. They verify that an **aggregated** signature is
//! valid for a given set of public keys and their corresponding messages, but they **do not
//! guarantee that each individual signature was valid prior to aggregation**.
//!
//! Because the verification evaluates the sum of the pairings without using random linear
//! combinations, it is mathematically possible for individually invalid signatures to cancel
//! each other out, resulting in a valid aggregate.
//!
//! This property is acceptable and expected in the context of the Solana Alpenglow consensus
//! protocol, where only the final aggregated signature is included on-chain. If your Rust
//! application requires strict proof that every single participant provided a valid signature
//! prior to aggregation, you must verify the signatures individually.

use {
    crate::{
        error::BlsError,
        hash::{HashedMessage, PreparedHashedMessage},
        prepared_g2::{multi_miller_loop, PreparedG2},
        pubkey::{AsPubkeyAffine, PopVerified},
        signature::{
            points::{AddToSignatureProjective, AsSignatureAffine, SignatureProjective},
            BLS_SIGNATURE_COMPRESSED_SIZE,
        },
    },
    blstrs::{G1Affine, G1Projective},
    core::borrow::Borrow,
    group::prime::PrimeCurveAffine,
};
#[cfg(feature = "parallel")]
use {alloc::vec::Vec, rayon::prelude::*};

/// A pairing term keyed by its compressed message hash, so equal messages can be grouped.
struct GroupedTerm<T> {
    message_key: [u8; BLS_SIGNATURE_COMPRESSED_SIZE],
    public_key: G1Affine,
    value: T,
}

impl<T> GroupedTerm<T> {
    fn new(
        public_key: G1Affine,
        (message_key, value): ([u8; BLS_SIGNATURE_COMPRESSED_SIZE], T),
    ) -> Self {
        Self {
            message_key,
            public_key,
            value,
        }
    }
}

fn raw_term(message: &[u8]) -> ([u8; BLS_SIGNATURE_COMPRESSED_SIZE], HashedMessage) {
    let hashed_message = HashedMessage::new(message);
    (hashed_message.0.to_compressed(), hashed_message)
}

fn hashed_term(
    hashed_message: &HashedMessage,
) -> ([u8; BLS_SIGNATURE_COMPRESSED_SIZE], &HashedMessage) {
    (hashed_message.0.to_compressed(), hashed_message)
}

fn prepared_term(
    prepared: &PreparedHashedMessage,
) -> ([u8; BLS_SIGNATURE_COMPRESSED_SIZE], &PreparedG2) {
    (
        prepared.hashed_message.0.to_compressed(),
        &prepared.prepared,
    )
}

/// Converts a public key for screening and rejects the identity.
fn screening_public_key<P: AsPubkeyAffine + ?Sized>(
    pubkey: &PopVerified<P>,
) -> Result<G1Affine, BlsError> {
    let public_key = pubkey.try_as_affine()?;
    if bool::from(public_key.0.is_identity()) {
        return Err(BlsError::VerificationFailed);
    }
    Ok(public_key.0)
}

#[allow(clippy::arithmetic_side_effects)]
fn hashed_message_pairing<T: Borrow<HashedMessage>>(entries: &[GroupedTerm<T>]) -> blst::blst_fp12 {
    // Compute each message term directly without temporary G2 tables.
    entries
        .iter()
        .map(|entry| {
            blst::blst_fp12::miller_loop(entry.value.borrow().0.as_ref(), entry.public_key.as_ref())
        })
        .reduce(|mut left, right| {
            left *= right;
            left
        })
        .unwrap_or_default()
}

#[cfg(feature = "parallel")]
#[allow(clippy::arithmetic_side_effects)]
fn par_hashed_message_pairing<T: Borrow<HashedMessage> + Sync>(
    entries: &[GroupedTerm<T>],
) -> blst::blst_fp12 {
    // Compute message pairings on workers without temporary G2 tables.
    entries
        .par_iter()
        .map(|entry| {
            blst::blst_fp12::miller_loop(entry.value.borrow().0.as_ref(), entry.public_key.as_ref())
        })
        .reduce_with(|mut left, right| {
            left *= right;
            left
        })
        .unwrap_or_default()
}

fn prepared_message_pairing(entries: &[GroupedTerm<&PreparedG2>]) -> blst::blst_fp12 {
    // Reuse the cached message tables.
    multi_miller_loop(entries.iter().map(|entry| (&entry.public_key, entry.value)))
}

impl SignatureProjective {
    /// Group pairing terms by message hash in `O(n log n)` time by sorting the terms and
    /// merging each run of equal hashes into its first term, which reuses the same buffer.
    fn group_terms_in_place<T: Send>(
        entries: &mut alloc::vec::Vec<GroupedTerm<T>>,
    ) -> Result<(), BlsError> {
        #[cfg(feature = "parallel")]
        entries.par_sort_unstable_by(|a, b| a.message_key.cmp(&b.message_key));
        #[cfg(not(feature = "parallel"))]
        entries.sort_unstable_by(|a, b| a.message_key.cmp(&b.message_key));

        for group in entries.chunk_by_mut(|a, b| a.message_key == b.message_key) {
            if let Some((first, rest)) = group.split_first_mut() {
                let mut aggregate_pubkey = G1Projective::from(first.public_key);
                for entry in rest {
                    #[allow(clippy::arithmetic_side_effects)]
                    {
                        aggregate_pubkey += &entry.public_key;
                    }
                }
                first.public_key = aggregate_pubkey.into();
            }
        }
        entries.dedup_by(|entry, group| entry.message_key == group.message_key);

        if entries
            .iter()
            .any(|entry| bool::from(entry.public_key.is_identity()))
        {
            return Err(BlsError::VerificationFailed);
        }
        Ok(())
    }

    /// Group the terms and compare their pairing with the aggregate signature.
    fn screen_terms<T: Send, S: AsSignatureAffine + ?Sized>(
        mut entries: alloc::vec::Vec<GroupedTerm<T>>,
        aggregate_signature: &S,
        message_pairing: impl FnOnce(&[GroupedTerm<T>]) -> blst::blst_fp12,
    ) -> Result<(), BlsError> {
        let aggregate_signature_affine = aggregate_signature.try_as_affine()?;
        Self::group_terms_in_place(&mut entries)?;

        let message_pairing = message_pairing(&entries);
        let generator = G1Affine::generator();
        let signature_pairing =
            blst::blst_fp12::miller_loop(aggregate_signature_affine.0.as_ref(), generator.as_ref());

        // Compare the pairings using one final exponentiation.
        blst::blst_fp12::finalverify(&message_pairing, &signature_pairing)
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
    }

    /// Build the terms on worker threads directly into the buffer that grouping reuses.
    #[cfg(feature = "parallel")]
    fn par_collect_terms<'b, P, M, T>(
        public_keys: &[PopVerified<P>],
        messages: &'b [M],
        message_term: impl Fn(&'b M) -> ([u8; BLS_SIGNATURE_COMPRESSED_SIZE], T) + Sync,
    ) -> Result<Vec<GroupedTerm<T>>, BlsError>
    where
        P: AsPubkeyAffine + Sync,
        M: Sync,
        T: Send,
    {
        // A key that fails conversion is stored as the identity, so the buffer holds plain terms.
        // Converting that key again reports the first failure in input order.
        let mut entries = Vec::with_capacity(public_keys.len());
        public_keys
            .par_iter()
            .zip(messages)
            .map(|(pubkey, message)| {
                GroupedTerm::new(
                    screening_public_key(pubkey).unwrap_or(G1Affine::identity()),
                    message_term(message),
                )
            })
            .collect_into_vec(&mut entries);

        for (entry, pubkey) in entries.iter().zip(public_keys) {
            if bool::from(entry.public_key.is_identity()) {
                return Err(screening_public_key(pubkey)
                    .err()
                    .unwrap_or(BlsError::VerificationFailed));
            }
        }
        Ok(entries)
    }

    /// Performs aggregate screening of signatures over distinct messages.
    ///
    /// This function groups signatures by message hash and verifies the aggregate relation per
    /// bucket. A successful result does not imply that every individual signature in the set is
    /// valid. Callers that require per-signer validity guarantees must verify each signature
    /// individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique to prevent rogue-key attacks. The messages can be
    /// identical or different.
    pub fn verify_distinct<'a, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        signatures: impl ExactSizeIterator<Item = &'a S>,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AddToSignatureProjective + 'a + ?Sized,
    {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated(public_keys, &aggregate_signature, messages)
    }

    /// Performs aggregate screening of signatures over distinct pre-hashed messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
    pub fn verify_distinct_pre_hashed<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        signatures: impl ExactSizeIterator<Item = &'a S>,
        hashed_messages: impl ExactSizeIterator<Item = &'b HashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AddToSignatureProjective + 'a + ?Sized,
    {
        if public_keys.len() != hashed_messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            hashed_messages,
        )
    }

    /// Performs aggregate screening of signatures over distinct prepared messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
    pub fn verify_distinct_prepared<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        signatures: impl ExactSizeIterator<Item = &'a S>,
        prepared_hashed_messages: impl ExactSizeIterator<Item = &'b PreparedHashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AddToSignatureProjective + 'a + ?Sized,
    {
        if public_keys.len() != prepared_hashed_messages.len()
            || public_keys.len() != signatures.len()
        {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated_prepared(
            public_keys,
            &aggregate_signature,
            prepared_hashed_messages,
        )
    }

    /// Performs aggregate screening with a pre-aggregated signature over distinct messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
    pub fn verify_distinct_aggregated<'a, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        aggregate_signature: &S,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AsSignatureAffine + ?Sized,
    {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let mut entries = alloc::vec::Vec::with_capacity(public_keys.len());
        for (pubkey, message) in public_keys.zip(messages) {
            entries.push(GroupedTerm::new(
                screening_public_key(pubkey)?,
                raw_term(message),
            ));
        }
        Self::screen_terms(entries, aggregate_signature, hashed_message_pairing)
    }

    /// Performs aggregate screening with a pre-aggregated signature over distinct pre-hashed
    /// messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
    pub fn verify_distinct_aggregated_pre_hashed<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        aggregate_signature: &S,
        hashed_messages: impl ExactSizeIterator<Item = &'b HashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AsSignatureAffine + ?Sized,
    {
        if public_keys.len() != hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let mut entries = alloc::vec::Vec::with_capacity(public_keys.len());
        for (pubkey, hashed_message) in public_keys.zip(hashed_messages) {
            entries.push(GroupedTerm::new(
                screening_public_key(pubkey)?,
                hashed_term(hashed_message),
            ));
        }
        Self::screen_terms(entries, aggregate_signature, hashed_message_pairing)
    }

    /// Performs aggregate screening with a pre-aggregated signature over distinct prepared
    /// messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Entries with identical message hashes are merged internally by summing
    /// their public keys, reducing pairing terms.
    ///
    /// Security note: rogue-key concerns are not relevant here because keys are
    /// assumed to be PoP-validated.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the iterator. It does *not* imply that the
    /// messages must be unique. The messages can be identical or different.
    pub fn verify_distinct_aggregated_prepared<'a, 'b, P, S>(
        public_keys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        aggregate_signature: &S,
        prepared_hashed_messages: impl ExactSizeIterator<Item = &'b PreparedHashedMessage>,
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + 'a + ?Sized,
        S: AsSignatureAffine + ?Sized,
    {
        if public_keys.len() != prepared_hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let mut entries = alloc::vec::Vec::with_capacity(public_keys.len());
        for (pubkey, prepared) in public_keys.zip(prepared_hashed_messages) {
            entries.push(GroupedTerm::new(
                screening_public_key(pubkey)?,
                prepared_term(prepared),
            ));
        }
        Self::screen_terms(entries, aggregate_signature, prepared_message_pairing)
    }

    /// Performs aggregate screening of signatures over distinct messages in parallel.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct<P, S>(
        public_keys: &[PopVerified<P>],
        signatures: &[S],
        messages: &[&[u8]],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AddToSignatureProjective + Sync,
    {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        Self::par_verify_distinct_aggregated(public_keys, &aggregate_signature, messages)
    }

    /// Performs aggregate screening of signatures over distinct pre-hashed messages in parallel.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_pre_hashed<P, S>(
        public_keys: &[PopVerified<P>],
        signatures: &[S],
        hashed_messages: &[HashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AddToSignatureProjective + Sync,
    {
        if public_keys.len() != hashed_messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        Self::par_verify_distinct_aggregated_pre_hashed(
            public_keys,
            &aggregate_signature,
            hashed_messages,
        )
    }

    /// Performs aggregate screening of signatures over distinct prepared messages in parallel.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_prepared<P, S>(
        public_keys: &[PopVerified<P>],
        signatures: &[S],
        prepared_hashed_messages: &[PreparedHashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AddToSignatureProjective + Sync,
    {
        if public_keys.len() != prepared_hashed_messages.len()
            || public_keys.len() != signatures.len()
        {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        Self::par_verify_distinct_aggregated_prepared(
            public_keys,
            &aggregate_signature,
            prepared_hashed_messages,
        )
    }

    /// Performs aggregate screening in parallel with a pre-aggregated signature over distinct
    /// messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated<P, S>(
        public_keys: &[PopVerified<P>],
        aggregate_signature: &S,
        messages: &[&[u8]],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AsSignatureAffine + Sync,
    {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let entries = Self::par_collect_terms(public_keys, messages, |message| raw_term(message))?;
        Self::screen_terms(entries, aggregate_signature, par_hashed_message_pairing)
    }

    /// Performs aggregate screening in parallel with a pre-aggregated signature over distinct
    /// pre-hashed messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated_pre_hashed<P, S>(
        public_keys: &[PopVerified<P>],
        aggregate_signature: &S,
        hashed_messages: &[HashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AsSignatureAffine + Sync,
    {
        if public_keys.len() != hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let entries = Self::par_collect_terms(public_keys, hashed_messages, hashed_term)?;
        Self::screen_terms(entries, aggregate_signature, par_hashed_message_pairing)
    }

    /// Performs aggregate screening in parallel with a pre-aggregated signature over distinct
    /// prepared messages.
    ///
    /// This function provides screening guarantees only. A successful result does not imply that
    /// every individual signature in the set is valid. Callers that require per-signer validity
    /// guarantees must verify each signature individually.
    ///
    /// Entries with identical message hashes are merged internally by summing
    /// their public keys, reducing pairing terms.
    ///
    /// Note: The term "distinct" indicates that each public key is paired with a
    /// corresponding message from the slice. It does *not* imply that the messages
    /// must be unique. The messages can be identical or different.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated_prepared<P, S>(
        public_keys: &[PopVerified<P>],
        aggregate_signature: &S,
        prepared_hashed_messages: &[PreparedHashedMessage],
    ) -> Result<(), BlsError>
    where
        P: AsPubkeyAffine + Sync,
        S: AsSignatureAffine + Sync,
    {
        if public_keys.len() != prepared_hashed_messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let entries =
            Self::par_collect_terms(public_keys, prepared_hashed_messages, prepared_term)?;
        Self::screen_terms(entries, aggregate_signature, prepared_message_pairing)
    }
}
