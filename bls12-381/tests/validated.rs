mod common;

use solana_bls12_381::{
    validated::{
        BigEndian, Encoding, LittleEndian, ValidG1, ValidG1Ref, ValidG1Slice, ValidG2, ValidG2Ref,
        ValidG2Slice,
    },
    Endianness, G1Compressed, G1Point, G2Compressed, G2Point, Scalar,
};

macro_rules! group_tests {
    ($test:ident, $point:ident, $owned:ident, $view:ident, $slice:ident, $size:expr, $torsion:ident) => {
        #[test]
        fn $test() {
            fn run<E: Encoding>() {
                let e = E::ENDIANNESS;
                let p = $point::generator(e);
                let q = p.mul(&Scalar::from_u64(7, e), e).unwrap();
                let vp = $view::<E>::validate(&p).unwrap();
                let vq = $owned::<E>::validate(q).unwrap();
                assert!(!vp.is_infinity());
                assert!($owned::<E>::infinity().as_ref().is_infinity());
                assert_eq!($owned::<E>::generator().into_point(), p);
                assert_eq!(vp.into_owned().into_point(), p);
                for (actual, expected) in [
                    (vp.add(vq.as_ref()), p.add(&q, e)),
                    (vp.sub(vq.as_ref()), p.sub(&q, e)),
                    (vp.neg(), p.neg(e)),
                    (vp.mul(&Scalar::from_u64(7, e)), Some(q)),
                    ($owned::<E>::from_mul(&p, &Scalar::from_u64(7, e)), Some(q)),
                ] {
                    let actual = actual.unwrap();
                    assert!(actual.as_point().validate(e));
                    assert_eq!(Some(actual.into_point()), expected);
                }
                assert!(vp.sub(vp).unwrap().as_ref().is_infinity());
                assert!(vp.mul(&Scalar::zero()).unwrap().as_ref().is_infinity());
                assert!(vp.mul(&Scalar([255; 32])).is_none());

                let points = [p, q, $point::infinity(e)];
                let valid = $slice::<E>::validate(&points).unwrap();
                assert_eq!(
                    valid.iter().map(|p| *p.as_point()).collect::<Vec<_>>(),
                    points,
                );
                assert_eq!($slice::<E>::validate(&[]).unwrap().iter().count(), 0);

                let torsion = common::$torsion(e);
                let mut malformed = $point::infinity(e);
                malformed.0[$size - 1] |= 1;
                for bad in [$point([0; $size]), $point([255; $size]), malformed, torsion] {
                    assert!($owned::<E>::validate(bad).is_none());
                    assert!($view::<E>::validate(&bad).is_none());
                    assert!($slice::<E>::validate(&[bad, p]).is_none());
                    assert!($slice::<E>::validate(&[p, p, bad]).is_none());
                    assert!($owned::<E>::from_mul(&bad, &Scalar::zero()).is_none());
                    assert!($owned::<E>::from_mul(&bad, &Scalar::one(e)).is_none());
                }
                let other_encoding = if e == Endianness::Big {
                    Endianness::Little
                } else {
                    Endianness::Big
                };
                assert!($view::<E>::validate(&$point::generator(other_encoding)).is_none());
            }
            run::<LittleEndian>();
            run::<BigEndian>();
        }
    };
}

group_tests!(
    g1_invariants,
    G1Point,
    ValidG1,
    ValidG1Ref,
    ValidG1Slice,
    96,
    g1_torsion
);
group_tests!(
    g2_invariants,
    G2Point,
    ValidG2,
    ValidG2Ref,
    ValidG2Slice,
    192,
    g2_torsion
);

#[test]
fn validated_decompression() {
    fn run<E: Encoding>() {
        let e = E::ENDIANNESS;
        assert!(ValidG1::<E>::decompress(&G1Compressed::infinity(e))
            .unwrap()
            .as_ref()
            .is_infinity());
        assert!(ValidG2::<E>::decompress(&G2Compressed::infinity(e))
            .unwrap()
            .as_ref()
            .is_infinity());
        assert!(ValidG1::<E>::decompress(&G1Compressed([0; 48])).is_none());
        assert!(ValidG2::<E>::decompress(&G2Compressed([0; 96])).is_none());
    }
    run::<LittleEndian>();
    run::<BigEndian>();
}
