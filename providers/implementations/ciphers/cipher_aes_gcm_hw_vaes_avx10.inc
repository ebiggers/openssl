/*
 * Copyright 2021-2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2021, Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES-GCM optimized with VAES, VPCLMULQDQ, and AVX512 or AVX10.
 * This file is included by cipher_aes_gcm_hw_aesni.inc
 */

#undef VAES_GCM_ENABLED
#if (defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined(_M_X64))
# define VAES_GCM_ENABLED

#ifndef BSWAP4
# define BSWAP4(v) \
        ((((u32)(v) & 0x000000FF) << 24) | \
         (((u32)(v) & 0x0000FF00) <<  8) | \
         (((u32)(v) & 0x00FF0000) >>  8) | \
         (((u32)(v) & 0xFF000000) >> 24))
#endif

#ifndef BSWAP8
# define BSWAP8(v) \
        ((((u64)(v) & 0x00000000000000FF) << 56) | \
         (((u64)(v) & 0x000000000000FF00) << 40) | \
         (((u64)(v) & 0x0000000000FF0000) << 24) | \
         (((u64)(v) & 0x00000000FF000000) <<  8) | \
         (((u64)(v) & 0x000000FF00000000) >>  8) | \
         (((u64)(v) & 0x0000FF0000000000) >> 24) | \
         (((u64)(v) & 0x00FF000000000000) >> 40) | \
         (((u64)(v) & 0xFF00000000000000) >> 56))
#endif

int aes_gcm_vaes_avx10_funcs_built(void);

void aes_gcm_precompute_vaes_avx10_256(const AES_KEY *key, u128 h_powers[16]);
void aes_gcm_precompute_vaes_avx10_512(const AES_KEY *key, u128 h_powers[16]);

void aes_gcm_gmult_vaes_avx10(const u128 h_powers[16], u8 ghash_acc[16]);
void aes_gcm_aad_update_vaes_avx10_256(const u128 h_powers[16], u8 ghash_acc[16],
                                       const u8 *aad, size_t aadlen);
void aes_gcm_aad_update_vaes_avx10_512(const u128 h_powers[16], u8 ghash_acc[16],
                                       const u8 *aad, size_t aadlen);

void aes_gcm_enc_update_vaes_avx10_256(const AES_KEY *aes_key, const u128 h_powers[16],
                                       const u32 le_ctr[4], u8 ghash_acc[16],
                                       const u8 *src, u8 *dst, size_t datalen);
void aes_gcm_dec_update_vaes_avx10_256(const AES_KEY *aes_key, const u128 h_powers[16],
                                       const u32 le_ctr[4], u8 ghash_acc[16],
                                       const u8 *src, u8 *dst, size_t datalen);
void aes_gcm_enc_update_vaes_avx10_512(const AES_KEY *aes_key, const u128 h_powers[16],
                                       const u32 le_ctr[4], u8 ghash_acc[16],
                                       const u8 *src, u8 *dst, size_t datalen);
void aes_gcm_dec_update_vaes_avx10_512(const AES_KEY *aes_key, const u128 h_powers[16],
                                       const u32 le_ctr[4], u8 ghash_acc[16],
                                       const u8 *src, u8 *dst, size_t datalen);

static int vaes_gcm_setkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    GCM128_CONTEXT *gcmctx = &ctx->gcm;
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    AES_KEY *ks = &actx->ks.ks;

    aesni_set_encrypt_key(key, keylen * 8, ks);
    memset(gcmctx, 0, sizeof(*gcmctx));
    gcmctx->key = ks;
    ctx->key_set = 1;

    aes_gcm_precompute_vaes_avx10_512(ks, gcmctx->Htable);

    return 1;
}

static int vaes_gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv,
                          size_t ivlen)
{
    GCM128_CONTEXT *gcmctx = &ctx->gcm;

    if (ivlen == 12) {
        u32 be_ctr[4];

        /* Generate the keystream block for encrypting the auth tag. */
        memcpy(be_ctr, iv, 12);
        be_ctr[3] = 0x01000000;
        aesni_encrypt((const u8 *)be_ctr, gcmctx->EK0.c, gcmctx->key);

        /* Build the starting counter for the data, in little endian format. */
        gcmctx->Yi.d[0] = 2;
        gcmctx->Yi.d[1] = BSWAP4(be_ctr[2]);
        gcmctx->Yi.d[2] = BSWAP4(be_ctr[1]);
        gcmctx->Yi.d[3] = BSWAP4(be_ctr[0]);
    } else {
        u64 tmp[4] = { 0 };
        size_t l;

        /* Bit length of IV cannot be >= 2^64. */
        if (ivlen >= 1ULL << 61)
            return 0;

        /* GHASH the IV to generate the counter. */
        gcmctx->Yi.u[0] = 0;
        gcmctx->Yi.u[1] = 0;
        aes_gcm_aad_update_vaes_avx10_512(gcmctx->Htable, gcmctx->Yi.c,
                                          iv, ivlen & ~15);
        iv += ivlen & ~15;
        if (ivlen & 15) {
            memcpy(tmp, iv, ivlen & 15);
            tmp[3] = BSWAP8((u64)ivlen * 8);
            l = 32;
        } else {
            tmp[1] = BSWAP8((u64)ivlen * 8);
            l = 16;
        }
        aes_gcm_aad_update_vaes_avx10_512(gcmctx->Htable, gcmctx->Yi.c,
                                          (const u8 *)tmp, l);

        /* Generate the keystream block for encrypting the auth tag. */
        tmp[0] = BSWAP8(gcmctx->Yi.u[1]);
        tmp[1] = BSWAP8(gcmctx->Yi.u[0]);
        aesni_encrypt((const u8 *)tmp, gcmctx->EK0.c, gcmctx->key);

        /* Build the starting counter for the data, in little endian format. */
        gcmctx->Yi.d[0]++;
    }
    gcmctx->Xi.u[0] = 0;       /* GHASH accumulator */
    gcmctx->Xi.u[1] = 0;
    gcmctx->len.u[0] = 0;      /* AAD length */
    gcmctx->len.u[1] = 0;      /* Message length */
    gcmctx->mres = 0;          /* Num bytes in pending partial block */

    return 1;
}

static int vaes_gcm_aadupdate(PROV_GCM_CTX *ctx,
                              const unsigned char *aad, size_t aad_len)
{
    GCM128_CONTEXT *gcmctx = &ctx->gcm;
    u64 total_aad_len;
    unsigned int mres;
    size_t bulk_len;

    /* Bad sequence: call of AAD update after message processing */
    if (gcmctx->len.u[1] > 0)
        return 0;

    total_aad_len = gcmctx->len.u[0] + aad_len;
    /* Bit length of AAD cannot be >= 2^64. */
    if (total_aad_len >= 1ULL << 61 || total_aad_len < aad_len)
        return 0;
    gcmctx->len.u[0] = total_aad_len;

    mres = gcmctx->mres;
    if (mres > 0) {
        /*
         * Continue gathering partial AAD block by XOR'ing AAD bytes into the
         * GHASH accumulator.  Note that it's stored byte-reflected.
         */
        if (aad_len <= 16 - mres) {
            for (; aad_len > 0; mres++, aad++, aad_len--)
                gcmctx->Xi.c[15 - mres] ^= *aad;
            gcmctx->mres = mres;
            return 1; /* Block is still partial. */
        }
        for (; mres < 16; mres++, aad++, aad_len--)
            gcmctx->Xi.c[15 - mres] ^= *aad;
        /* Full block gathered */
        aes_gcm_gmult_vaes_avx10(gcmctx->Htable, gcmctx->Xi.c);
        gcmctx->mres = 0;
    }

    /* GHASH whole blocks of AAD. */
    bulk_len = aad_len & ~15;
    if (bulk_len > 0) {
        aes_gcm_aad_update_vaes_avx10_512(gcmctx->Htable, gcmctx->Xi.c,
                                          aad, bulk_len);
        aad += bulk_len;
        aad_len -= bulk_len;
    }

    /* If a partial block of AAD remains, start gathering it. */
    if (aad_len) {
        for (mres = 0; mres < aad_len; mres++)
            gcmctx->Xi.c[15 - mres] ^= aad[mres];
        gcmctx->mres = mres;
    }
    return 1;
}

static int vaes_gcm_cipherupdate(PROV_GCM_CTX *ctx, const unsigned char *in,
                                 size_t len, unsigned char *out)
{
    GCM128_CONTEXT *gcmctx = &ctx->gcm;
    u64 total_len;
    unsigned int mres;
    size_t bulk_len;

    total_len = gcmctx->len.u[1] + len;
    if (total_len > (1ULL << 36) - 32 || total_len < len)
        return 0;
    gcmctx->len.u[1] = total_len;

    mres = gcmctx->mres;
    if (mres) {
        if (len < total_len) {
            /*
             * Continue filling a partial message block:
             *
             * - Generate the output data bytes by XOR'ing input with the
             *   keystream.  This has to be done even if the block is still
             *   partial, to comply with OpenSSL's API.
             * - XOR the ciphertext bytes (output if encrypting, input if
             *   decrypting) into the GHASH accumulator.  Note that the GHASH
             *   accumulator is stored byte-reflected.
             */
            if (len <= 16 - mres) {
                for (; len > 0; mres++, in++, out++, len--) {
                    u8 in_byte = *in;
                    u8 out_byte = in_byte ^ gcmctx->EKi.c[mres];

                    *out = out_byte;
                    gcmctx->Xi.c[15 - mres] ^= ctx->enc ? out_byte : in_byte;
                }
                gcmctx->mres = mres;
                return 1; /* Block is still partial. */
            }
            for (; mres < 16; mres++, in++, out++, len--) {
                u8 in_byte = *in;
                u8 out_byte = in_byte ^ gcmctx->EKi.c[mres];

                *out = out_byte;
                gcmctx->Xi.c[15 - mres] ^= ctx->enc ? out_byte : in_byte;
            }
            /* Full block gathered */
        } /* AAD ended with a partial block; zero-pad and GHASH it. */
        gcmctx->mres = 0;
        aes_gcm_gmult_vaes_avx10(gcmctx->Htable, gcmctx->Xi.c);
    }

    /* En/decrypt whole blocks. */
    bulk_len = len & ~15;
    if (ctx->enc)
        aes_gcm_enc_update_vaes_avx10_512(gcmctx->key, gcmctx->Htable,
                                          gcmctx->Yi.d, gcmctx->Xi.c,
                                          in, out, bulk_len);
    else
        aes_gcm_dec_update_vaes_avx10_512(gcmctx->key, gcmctx->Htable,
                                          gcmctx->Yi.d, gcmctx->Xi.c,
                                          in, out, bulk_len);
    gcmctx->Yi.d[0] += len / 16;
    in += bulk_len;
    out += bulk_len;
    len -= bulk_len;

    /* If a partial block remains, start gathering it. */
    if (len) {
        u64 be_ctr[2] = { BSWAP8(gcmctx->Yi.u[1]), BSWAP8(gcmctx->Yi.u[0]) };

        aesni_encrypt((const u8 *)be_ctr, gcmctx->EKi.c, gcmctx->key);
        gcmctx->Yi.d[0]++;
        for (mres = 0; mres < len; mres++, in++, out++) {
            u8 in_byte = *in;
            u8 out_byte = in_byte ^ gcmctx->EKi.c[mres];

            *out = out_byte;
            gcmctx->Xi.c[15 - mres] ^= ctx->enc ? out_byte : in_byte;
        }
        gcmctx->mres = mres;
    }
    return 1;
}

static int vaes_gcm_cipherfinal(PROV_GCM_CTX *ctx, unsigned char *tag)
{
    GCM128_CONTEXT *gcmctx = &ctx->gcm;
    u64 computed_tag[2];

    /* If there's a partial AAD or ciphertext block, zero-pad and GHASH it. */
    if (gcmctx->mres)
        aes_gcm_gmult_vaes_avx10(gcmctx->Htable, gcmctx->Xi.c);

    /* GHASH the lengths block. */
    gcmctx->Xi.u[0] ^= 8 * gcmctx->len.u[1]; /* Data length in bits */
    gcmctx->Xi.u[1] ^= 8 * gcmctx->len.u[0]; /* AAD length in bits */
    aes_gcm_gmult_vaes_avx10(gcmctx->Htable, gcmctx->Xi.c);

    /*
     * Generate the auth tag by encrypting the GHASH accumulator using the
     * keystream block previously computed.
     */
    computed_tag[0] = BSWAP8(gcmctx->Xi.u[1]) ^ gcmctx->EK0.u[0];
    computed_tag[1] = BSWAP8(gcmctx->Xi.u[0]) ^ gcmctx->EK0.u[1];

    if (ctx->enc) {
        /* Return the computed tag. */
        ctx->taglen = GCM_TAG_MAX_SIZE;
        memcpy(tag, computed_tag, GCM_TAG_MAX_SIZE);
        return 1;
    }
    /* Compare the tags. */
    return !CRYPTO_memcmp(computed_tag, tag, ctx->taglen);
}

static const PROV_GCM_HW vaes_gcm = {
    vaes_gcm_setkey,
    vaes_gcm_setiv,
    vaes_gcm_aadupdate,
    vaes_gcm_cipherupdate,
    vaes_gcm_cipherfinal,
    ossl_gcm_one_shot
};

#endif
