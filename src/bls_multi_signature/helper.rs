pub(crate) mod unsafe_helpers {
    use blst::{
        blst_fp12, blst_fp12_finalverify, blst_fp12_mul, blst_p1, blst_p1_add, blst_p1_affine,
        blst_p1_affine_generator, blst_p1_compress, blst_p1_from_affine, blst_p1_to_affine,
        blst_p1_uncompress, blst_p2, blst_p2_add, blst_p2_affine, blst_p2_affine_generator,
        blst_p2_from_affine, blst_p2_to_affine, blst_scalar, blst_sk_to_pk_in_g1,
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
            blst_p1_add(&mut projective_p1, p, q);
            projective_p1
        }
    }

    pub(crate) fn p2_add(p: &blst_p2, q: &blst_p2) -> blst_p2 {
        unsafe {
            let mut projective_p2 = blst_p2::default();
            blst_p2_add(&mut projective_p2, p, q);
            projective_p2
        }
    }
}
