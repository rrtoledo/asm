pub(crate) mod unsafe_helpers {
    use blst::{
        blst_fp12, blst_fp12_finalverify, blst_fp12_mul, blst_p1, blst_p1_add_or_double,
        blst_p1_affine, blst_p1_affine_generator, blst_p1_compress, blst_p1_from_affine,
        blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress, blst_p2, blst_p2_add_or_double,
        blst_p2_affine, blst_p2_affine_generator, blst_p2_from_affine, blst_p2_mult,
        blst_p2_to_affine, blst_scalar, blst_sk_to_pk_in_g1,
        min_sig::{PublicKey as BlstVk, SecretKey as BlstSk, Signature as BlstSig},
    };

    use crate::bls_multi_signature::{BlsProofOfPossession, BlsVerificationKey};
    use crate::error::{MultiSignatureError, MultiSignatureError::SerializationError};

    /// Check manually if the pairing `e(g1,mvk) = e(k2,g2)` holds.
    pub(crate) fn verify_pairing(vk: &BlsVerificationKey, pop: &BlsProofOfPossession) -> bool {
        unsafe {
            let g1_p = *blst_p1_affine_generator();
            let mvk_p =
                std::mem::transmute::<BlstVk, blst_p2_affine>(vk.to_blst_verification_key());
            let ml_lhs = blst_fp12::miller_loop(&mvk_p, &g1_p);

            let mut k2_p = blst_p1_affine::default();
            blst_p1_to_affine(&mut k2_p, &pop.get_k2());
            let g2_p = *blst_p2_affine_generator();
            let ml_rhs = blst_fp12::miller_loop(&g2_p, &k2_p);

            blst_fp12_finalverify(&ml_lhs, &ml_rhs)
        }
    }

    /// Check manually if the pairing `e(σ1,g2) = e(p1_1, vk) * e(p1_2,σ2)` holds.
    pub(crate) fn verify_double_pairing(
        vk: &BlsVerificationKey,
        sigma_1: &BlstSig,
        sigma_2: &BlsVerificationKey,
        p1_vk: &BlstSig,
        p1_sigma2: &BlstSig,
    ) -> bool {
        unsafe {
            // e(σ1,g2)
            let k2_p: blst_p1_affine = std::mem::transmute::<BlstSig, blst_p1_affine>(*sigma_1);
            let g2_p = *blst_p2_affine_generator();
            let ml_lhs = blst_fp12::miller_loop(&g2_p, &k2_p);

            // e(p1_1, vk)
            let k1a_p = std::mem::transmute::<BlstSig, blst_p1_affine>(*p1_vk);
            let mvk_p =
                std::mem::transmute::<BlstVk, blst_p2_affine>(vk.to_blst_verification_key());
            let ml_rhs1 = blst_fp12::miller_loop(&mvk_p, &k1a_p);

            // e(p1_2, σ2)
            let k1b_p = std::mem::transmute::<BlstSig, blst_p1_affine>(*p1_sigma2);
            let sig2_p =
                std::mem::transmute::<BlstVk, blst_p2_affine>(sigma_2.to_blst_verification_key());
            let ml_rhs2 = blst_fp12::miller_loop(&sig2_p, &k1b_p);

            // e(p1_1, vk) * e(p1_2, σ2)
            let mut ml_rhs = blst_fp12::default();
            blst_fp12_mul(&mut ml_rhs, &ml_rhs1, &ml_rhs2);

            blst_fp12_finalverify(&ml_lhs, &ml_rhs)
        }
    }

    pub(crate) fn compress_p1(k2: &blst_p1) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        unsafe { blst_p1_compress(bytes.as_mut_ptr(), k2) }
        bytes
    }

    pub(crate) fn uncompress_p1(bytes: &[u8]) -> Result<blst_p1, MultiSignatureError> {
        unsafe {
            if bytes.len() == 48 {
                let mut point = blst_p1_affine::default();
                let mut out = blst_p1::default();
                blst_p1_uncompress(&mut point, bytes.as_ptr());
                blst_p1_from_affine(&mut out, &point);
                Ok(out)
            } else {
                Err(SerializationError)
            }
        }
    }

    pub(crate) fn scalar_to_pk_in_g1(sk: &BlstSk) -> blst_p1 {
        unsafe {
            let sk_scalar = std::mem::transmute::<&BlstSk, &blst_scalar>(sk);
            let mut out = blst_p1::default();
            blst_sk_to_pk_in_g1(&mut out, sk_scalar);
            out
        }
    }

    pub(crate) fn vk_from_p2_affine(vk: &BlsVerificationKey) -> blst_p2 {
        unsafe {
            let mut projective_p2 = blst_p2::default();
            blst_p2_from_affine(
                &mut projective_p2,
                &std::mem::transmute::<BlstVk, blst_p2_affine>(vk.to_blst_verification_key()),
            );
            projective_p2
        }
    }

    pub(crate) fn sig_to_p1(sig: &BlstSig) -> blst_p1 {
        unsafe {
            let mut projective_p1 = blst_p1::default();
            blst_p1_from_affine(
                &mut projective_p1,
                &std::mem::transmute::<BlstSig, blst_p1_affine>(*sig),
            );
            projective_p1
        }
    }

    pub(crate) fn p2_affine_to_vk(grouped_vks: &blst_p2) -> BlstVk {
        unsafe {
            let mut affine_p2 = blst_p2_affine::default();
            blst_p2_to_affine(&mut affine_p2, grouped_vks);
            std::mem::transmute::<blst_p2_affine, BlstVk>(affine_p2)
        }
    }

    pub(crate) fn p1_affine_to_sig(grouped_sigs: &blst_p1) -> BlstSig {
        unsafe {
            let mut affine_p1 = blst_p1_affine::default();
            blst_p1_to_affine(&mut affine_p1, grouped_sigs);
            std::mem::transmute::<blst_p1_affine, BlstSig>(affine_p1)
        }
    }

    pub(crate) fn p1_add(p: &blst_p1, q: &blst_p1) -> blst_p1 {
        unsafe {
            let mut projective_p1 = blst_p1::default();
            blst_p1_add_or_double(&mut projective_p1, p, q);
            projective_p1
        }
    }

    pub(crate) fn p1_mul(p: &blst_p1, r: &[u8], nbits: usize) -> blst_p1 {
        unsafe {
            let mut projective_p1 = blst_p1::default();
            blst_p1_mult(&mut projective_p1, p, r.as_ptr(), nbits);
            projective_p1
        }
    }

    pub(crate) fn p2_add(p: &blst_p2, q: &blst_p2) -> blst_p2 {
        unsafe {
            let mut projective_p2 = blst_p2::default();
            blst_p2_add_or_double(&mut projective_p2, p, q);
            projective_p2
        }
    }

    pub(crate) fn p2_mul(p: &blst_p2, r: &[u8], nbits: usize) -> blst_p2 {
        unsafe {
            let mut projective_p2 = blst_p2::default();
            blst_p2_mult(&mut projective_p2, p, r.as_ptr(), nbits);
            projective_p2
        }
    }

    pub(crate) fn fr_one() -> BlstSk {
        let mut vec_one = Vec::with_capacity(255);
        vec_one.push(1u8);

        for _ in 0..31 {
            vec_one.push(0u8);
        }

        BlstSk::from_bytes(&vec_one).unwrap()
    }

    pub(crate) fn fr_two() -> BlstSk {
        let mut vec_two: Vec<u8> = Vec::with_capacity(255);
        vec_two.push(2u8);

        for _ in 0..31 {
            vec_two.push(0u8);
        }

        BlstSk::from_bytes(&vec_two).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::unsafe_helpers::*;

    #[test]
    fn test_g1_one() {
        let one = fr_one();
        let two = fr_two();

        // Generating random point on G1
        let p1 = sig_to_p1(&one.sign(&[42], &[], &[]));
        let mut one_bytes = [0u8; 32];
        one_bytes[0] = 1u8;

        // Generating p1^1
        let p1_mul = p1_mul(&p1, &one_bytes, 256);

        // If we are multiplying by 1, the values should be the same
        // p.s. we are checking in Affine coordinates as we have no guarantees that the projective Z coordinate would be the same.
        assert!(p1_affine_to_sig(&p1) == p1_affine_to_sig(&p1_mul));

        // Further check verifying that P + P = P^2
        let p2 = sig_to_p1(&two.sign(&[42], &[], &[]));
        let p2_added = p1_add(&p1, &p1);
        assert_eq!(p1_affine_to_sig(&p2), p1_affine_to_sig(&p2_added));
    }

    #[test]
    fn test_g1_mul() {
        let one = fr_one();

        // Generating random point on G1
        let p1 = sig_to_p1(&one.sign(&[42], &[], &[]));
        let mut big_bytes = [0u8; 32];
        big_bytes[1] = 1u8;
        big_bytes[0] = 2u8;

        // Verifying endianness
        let number: usize = 256 + 2;
        assert_eq!(big_bytes[0..8], number.to_le_bytes());

        // Generating p1^1
        let p1_mul = p1_mul(&p1, &big_bytes, 256);

        let mut p1_added = p1_add(&p1, &p1);
        for _ in 0..(number - 2) {
            p1_added = p1_add(&p1_added, &p1);
        }

        // If we are multiplying by 1, the values should be the same
        // p.s. we are checking in Affine coordinates as we have no guarantees that the projective Z coordinate would be the same.
        assert!(p1_affine_to_sig(&p1_mul) == p1_affine_to_sig(&p1_added));
    }
}
