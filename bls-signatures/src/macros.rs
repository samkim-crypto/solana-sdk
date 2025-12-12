macro_rules! impl_from_str {
    (TYPE = $type:ident, BYTES_LEN = $bytes_len:expr, BASE64_LEN = $base64_len:expr) => {
        impl core::str::FromStr for $type {
            type Err = crate::error::BlsError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use base64::Engine;

                if s.len() > $base64_len {
                    return Err(Self::Err::ParseFromString);
                }
                let mut bytes = [0u8; $bytes_len];
                let decoded_len = base64::prelude::BASE64_STANDARD
                    .decode_slice(s, &mut bytes)
                    .map_err(|_| Self::Err::ParseFromString)?;
                if decoded_len != $bytes_len {
                    Err(Self::Err::ParseFromString)
                } else {
                    Ok($type(bytes))
                }
            }
        }
    };
}

/// A macro to implement the standard set of conversions between BLS projective,
/// affine (point), uncompressed (bytes), and compressed (bytes) representations.
#[cfg(not(target_os = "solana"))]
macro_rules! impl_bls_conversions {
    (
        $projective:ident,       // e.g. PubkeyProjective
        $affine:ident,           // e.g. PubkeyAffine
        $uncompressed:ident,     // e.g. Pubkey (Bytes)
        $compressed:ident,       // e.g. PubkeyCompressed (Bytes)
        $blstrs_affine:ty,       // e.g. blstrs::G1Affine
        $blstrs_projective:ty,   // e.g. blstrs::G1Projective
        $as_projective_trait:ident, // e.g. AsPubkeyProjective
        $as_affine_trait:ident,     // e.g. AsPubkeyAffine
        $compressed_size:ident,     // e.g. BLS_PUBLIC_KEY_COMPRESSED_SIZE
        $uncompressed_size:ident    // e.g. BLS_PUBLIC_KEY_AFFINE_SIZE
    ) => {
        // Math Conversions (Projective <-> Affine)
        impl From<&$projective> for $affine {
            fn from(p: &$projective) -> Self {
                $affine(<$blstrs_affine>::from(p.0))
            }
        }

        impl From<$projective> for $affine {
            fn from(p: $projective) -> Self {
                Self::from(&p)
            }
        }

        impl From<&$affine> for $projective {
            fn from(p: &$affine) -> Self {
                Self(<$blstrs_projective>::from(p.0))
            }
        }

        impl From<$affine> for $projective {
            fn from(p: $affine) -> Self {
                Self::from(&p)
            }
        }

        // Serialization (Affine Point <-> Bytes)
        // Affine Point -> Uncompressed Bytes
        impl From<&$affine> for $uncompressed {
            fn from(p: &$affine) -> Self {
                Self(p.0.to_uncompressed())
            }
        }
        impl From<$affine> for $uncompressed {
            fn from(p: $affine) -> Self {
                Self::from(&p)
            }
        }

        // Affine Point -> Compressed Bytes
        impl From<&$affine> for $compressed {
            fn from(p: &$affine) -> Self {
                Self(p.0.to_compressed())
            }
        }
        impl From<$affine> for $compressed {
            fn from(p: $affine) -> Self {
                Self::from(&p)
            }
        }

        // Projective -> Uncompressed Bytes (Delegates to Affine)
        impl From<&$projective> for $uncompressed {
            fn from(p: &$projective) -> Self {
                let affine = $affine::from(p);
                affine.into()
            }
        }
        impl From<$projective> for $uncompressed {
            fn from(p: $projective) -> Self {
                Self::from(&p)
            }
        }

        // Projective -> Compressed Bytes (Delegates to Affine)
        impl From<&$projective> for $compressed {
            fn from(p: &$projective) -> Self {
                let affine = $affine::from(p);
                affine.into()
            }
        }
        impl From<$projective> for $compressed {
            fn from(p: $projective) -> Self {
                Self::from(&p)
            }
        }

        // Uncompressed Bytes -> Affine Point
        impl TryFrom<&$uncompressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$uncompressed) -> Result<Self, Self::Error> {
                let maybe_point: Option<$blstrs_affine> =
                    <$blstrs_affine>::from_uncompressed(&bytes.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point))
            }
        }
        impl TryFrom<$uncompressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $uncompressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Compressed Bytes -> Affine Point
        impl TryFrom<&$compressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$compressed) -> Result<Self, Self::Error> {
                let maybe_point: Option<$blstrs_affine> =
                    <$blstrs_affine>::from_compressed(&bytes.0).into();
                let point = maybe_point.ok_or(crate::error::BlsError::PointConversion)?;
                Ok(Self(point))
            }
        }
        impl TryFrom<$compressed> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Transit Conversions (Projective <-> Bytes via Affine)
        impl TryFrom<&$uncompressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$uncompressed) -> Result<Self, Self::Error> {
                let affine = $affine::try_from(bytes)?;
                Ok(affine.into())
            }
        }
        impl TryFrom<$uncompressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $uncompressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        impl TryFrom<&$compressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &$compressed) -> Result<Self, Self::Error> {
                let affine = $affine::try_from(bytes)?;
                Ok(affine.into())
            }
        }
        impl TryFrom<$compressed> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: $compressed) -> Result<Self, Self::Error> {
                Self::try_from(&bytes)
            }
        }

        // Raw Byte Array Conversions ([u8; N] -> Types)
        // Raw Uncompressed ([u8; 96]) -> All Types
        impl TryFrom<&[u8; $uncompressed_size]> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $uncompressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $uncompressed(*bytes);
                Self::try_from(&wrapper)
            }
        }
        impl TryFrom<&[u8; $uncompressed_size]> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $uncompressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $uncompressed(*bytes);
                Self::try_from(&wrapper)
            }
        }
        // Raw Compressed ([u8; 48]) -> All Types
        impl TryFrom<&[u8; $compressed_size]> for $affine {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $compressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $compressed(*bytes);
                Self::try_from(&wrapper)
            }
        }
        impl TryFrom<&[u8; $compressed_size]> for $projective {
            type Error = crate::error::BlsError;
            fn try_from(bytes: &[u8; $compressed_size]) -> Result<Self, Self::Error> {
                let wrapper = $compressed(*bytes);
                Self::try_from(&wrapper)
            }
        }

        // Trait Implementations (AsProjective / AsAffine)
        // AsProjective
        impl $as_projective_trait for $projective {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                Ok(*self)
            }
        }
        impl $as_projective_trait for $affine {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                Ok(self.into())
            }
        }
        impl $as_projective_trait for $uncompressed {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                $projective::try_from(self)
            }
        }
        impl $as_projective_trait for $compressed {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                $projective::try_from(self)
            }
        }
        impl $as_projective_trait for [u8; $uncompressed_size] {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                let wrapper = $uncompressed(*self);
                $projective::try_from(&wrapper)
            }
        }
        impl $as_projective_trait for [u8; $compressed_size] {
            fn try_as_projective(&self) -> Result<$projective, crate::error::BlsError> {
                let wrapper = $compressed(*self);
                $projective::try_from(&wrapper)
            }
        }

        // AsAffine
        impl $as_affine_trait for $affine {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                Ok(*self)
            }
        }
        impl $as_affine_trait for $projective {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                Ok(self.into())
            }
        }
        impl $as_affine_trait for $uncompressed {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                $affine::try_from(self)
            }
        }
        impl $as_affine_trait for $compressed {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                $affine::try_from(self)
            }
        }
        impl $as_affine_trait for [u8; $uncompressed_size] {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                let wrapper = $uncompressed(*self);
                $affine::try_from(&wrapper)
            }
        }
        impl $as_affine_trait for [u8; $compressed_size] {
            fn try_as_affine(&self) -> Result<$affine, crate::error::BlsError> {
                let wrapper = $compressed(*self);
                $affine::try_from(&wrapper)
            }
        }
    };
}
