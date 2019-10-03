/* cavium_octeon.c
 *
 * Copyright(C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.(formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 *(at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef HAVE_CAVIUM_OCTEON

#include <wolfssl/wolfcrypt/port/cavium/cavium_octeon.h>

#ifndef NO_DES3
int Octeon_Des3_CbcEncrypt(Des3* des3, uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, r0;
    uint64_t *key, *iv;

    if (des3 == NULL || inp64 == NULL || outp64 == NULL)
        return BAD_FUNC_ARG;

    /* expects 64-bit aligned value */
    key = (uint64_t*)des3->key;
    CVMX_MT_3DES_KEY(key[0], 0);
    CVMX_MT_3DES_KEY(key[1], 1);
    CVMX_MT_3DES_KEY(key[2], 2);
    iv = (uint64_t*)des3->reg;
    CVMX_MT_3DES_IV(iv[0]);

    CVMX_PREFETCH0(inp64);

    i0 = *inp64;

    /* DES3 assembly can handle 16-byte chunks */
    if (inl >= 16) {
        CVMX_MT_3DES_ENC_CBC(i0);
        inl -= 8;
        inp64++;
        outp64++;

        if (inl >= 8) {
           i0 = inp64[0];
           CVMX_MF_3DES_RESULT(r0);
           CVMX_MT_3DES_ENC_CBC(i0);

            for (;;) {
                outp64[-1] = r0;
                inl -= 8;
                inp64++;
                outp64++;
                i0 = *inp64;

                if (inl < 8)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_3DES_RESULT(r0);
                CVMX_MT_3DES_ENC_CBC(i0);
            }
        }
        CVMX_MF_3DES_RESULT(r0);
        outp64[-1] = r0;
    }
    /* remainder */
    if (inl > 0) {
        uint64_t r = 0;
        if (inl <= 8) {
            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_ENC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
        else {
            i0 = *inp64;
            CVMX_MT_3DES_ENC_CBC(i0);
            CVMX_MF_3DES_RESULT(*outp64);
            inp64++, outp64++;

            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_ENC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
    }

    CVMX_MT_3DES_IV(iv[0]);

    return 0;
}

int Octeon_Des3_CbcDecrypt(Des3* des3, uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, r0;
    uint64_t *key, *iv;

    if (des3 == NULL || inp64 == NULL || outp64 == NULL)
        return BAD_FUNC_ARG;

    /* expects 64-bit aligned value */
    key = (uint64_t*)des3->key;
    CVMX_MT_3DES_KEY(key[0], 0);
    CVMX_MT_3DES_KEY(key[1], 1);
    CVMX_MT_3DES_KEY(key[2], 2);

    iv = (uint64_t*)des3->reg;
    CVMX_MT_3DES_IV(iv[0]);

    CVMX_PREFETCH0(inp64);

    i0 = *inp64;

    /* DES3 assembly can handle 16-byte chunks */
    if (inl >= 16) {
        CVMX_MT_3DES_DEC_CBC(i0);
        inl -= 8;
        inp64++;
        outp64++;

        if (inl >= 8) {
            i0 = inp64[0];
            CVMX_MF_3DES_RESULT(r0);
            CVMX_MT_3DES_DEC_CBC(i0);

            for (;;) {
                outp64[-1] = r0;
                inl -= 8;
                inp64++;
                outp64++;
                i0 = *inp64;

                if (inl < 8)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_3DES_RESULT(r0);
                CVMX_MT_3DES_DEC_CBC(i0);
            }
        }

        CVMX_MF_3DES_RESULT(r0);
        outp64[-1] = r0;
    }
    /* remainder */
    if (inl > 0) {
        if (inl <= 8) {
            uint64_t r = 0;
            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_DEC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
        else {
            uint64_t r = 0;
            i0 = *inp64;
            CVMX_MT_3DES_DEC_CBC(i0);
            CVMX_MF_3DES_RESULT(*outp64);
            inp64++, outp64++;

            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_DEC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
    }

    CVMX_MT_3DES_IV(iv[0]);

    return 0;
}
#endif /* !NO_DES3 */


#ifndef NO_AES

#ifdef WOLFSSL_AES_DIRECT
/* Perform Single Block ECB Encrypt */
int Octeon_AesEcb_Encrypt(Aes* aes, const unsigned char *in, unsigned char *out)
{
    uint64_t *in64, *out64, *key;

    if (aes == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    key = (uint64_t*)aes->key;
    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);
    CVMX_MT_AES_KEYLENGTH(aes->keylen/8 - 1);

    in64 = (uint64_t*)in;
    out64 = (uint64_t*)out;

    CVMX_MT_AES_ENC0(in64[0]);
    CVMX_MT_AES_ENC1(in64[1]);
    CVMX_MF_AES_RESULT(out64[0],0);
    CVMX_MF_AES_RESULT(out64[1],1);

    return 0;
}

/* Perform Single Block ECB Decrypt */
int Octeon_AesEcb_Decrypt(Aes* aes, const unsigned char *in, unsigned char *out)
{
    uint64_t *in64, *out64, *key;

    if (aes == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    key = (uint64_t*)aes->key;
    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);
    CVMX_MT_AES_KEYLENGTH(aes->keylen/8 - 1);

    in64 = (uint64_t*)in;
    out64 = (uint64_t*)out;
    CVMX_MT_AES_DEC0(in64[0]);
    CVMX_MT_AES_DEC1(in64[1]);
    CVMX_MF_AES_RESULT(out64[0],0);
    CVMX_MF_AES_RESULT(out64[1],1);

    return 0;
}
#endif /* WOLFSSL_AES_DIRECT */

#ifdef HAVE_AES_CBC
int Octeon_AesCbc_Encrypt(Aes *aes, uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, i1, r0, r1;
    uint64_t *key, *iv;

    if (aes == NULL || inp64 == NULL || outp64 == NULL) {
        return BAD_FUNC_ARG;
    }

    iv = (uint64_t*)aes->reg;
    CVMX_MT_AES_IV(iv[0], 0);
    CVMX_MT_AES_IV(iv[1], 1);

    key = (uint64_t*)aes->key;
    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);

    CVMX_MT_AES_KEYLENGTH(aes->keylen/8 - 1);

    CVMX_PREFETCH0(inp64);

    i0 = inp64[0];
    i1 = inp64[1];

    /* AES assembly can handle 32-byte chunks */
    if (inl >= 32) {
        CVMX_MT_AES_ENC_CBC0(i0);
        CVMX_MT_AES_ENC_CBC1(i1);
        inl -= 16;
        inp64  += 2;
        outp64 += 2;

        if (inl >= 16) {
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            i0 = inp64[0];
            i1 = inp64[1];
            CVMX_MT_AES_ENC_CBC0(i0);
            CVMX_MT_AES_ENC_CBC1(i1);

            for (;;) {
                outp64[-2] = r0;
                outp64[-1] = r1;
                outp64 += 2;
                inp64 += 2;
                inl -= 16;
                i0 = inp64[0];
                i1 = inp64[1];

                if (inl < 16)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                CVMX_MT_AES_ENC_CBC0(i0);
                CVMX_MT_AES_ENC_CBC1(i1);
            }
        }

        CVMX_MF_AES_RESULT(r0, 0);
        CVMX_MF_AES_RESULT(r1, 1);
        outp64[-2] = r0;
        outp64[-1] = r1;
    }
    /* remainder */
    if (inl > 0) {
        uint64_t in64[2] = { 0, 0 };
        if (inl <= 16) {
            XMEMCPY(in64, inp64, inl);
            CVMX_MT_AES_ENC_CBC0(in64[0]);
            CVMX_MT_AES_ENC_CBC1(in64[1]);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[0] = r0;
            outp64[1] = r1;
        }
        else {
            CVMX_MT_AES_ENC_CBC0(i0);
            CVMX_MT_AES_ENC_CBC1(i1);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            inl -= 16;
            outp64[0] = r0;
            outp64[1] = r1;
            inp64 += 2;
            outp64 += 2;
            XMEMCPY(in64, inp64, inl);
            CVMX_MT_AES_ENC_CBC0(in64[0]);
            CVMX_MT_AES_ENC_CBC1(in64[1]);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[0] = r0;
            outp64[1] = r1;
        }
    }

    CVMX_MF_AES_IV(iv[0], 0);
    CVMX_MF_AES_IV(iv[1], 1);

    return 0;
}

int Octeon_AesCbc_Decrypt(Aes *aes, uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, i1, r0, r1;
    uint64_t *key, *iv;

    if (aes == NULL || inp64 == NULL || outp64 == NULL) {
        return BAD_FUNC_ARG;
    }

    iv = (uint64_t*)aes->reg;
    key = (uint64_t*)aes->key;

    CVMX_MT_AES_IV(iv[0], 0);
    CVMX_MT_AES_IV(iv[1], 1);

    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);
    CVMX_MT_AES_KEYLENGTH(aes->keylen/8 - 1);

    CVMX_PREFETCH0(inp64);

    i0 = inp64[0];
    i1 = inp64[1];

    /* AES assembly can handle 32-byte chunks */
    if (inl >= 32) {
        CVMX_MT_AES_DEC_CBC0(i0);
        CVMX_MT_AES_DEC_CBC1(i1);
        inp64 += 2;
        outp64 += 2;
        inl -= 16;

        if (inl >= 16) {
            i0 = inp64[0];
            i1 = inp64[1];
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            CVMX_MT_AES_DEC_CBC0(i0);
            CVMX_MT_AES_DEC_CBC1(i1);

            for (;;) {
                outp64[-2] = r0;
                outp64[-1] = r1;
                outp64 += 2;
                inp64 += 2;
                inl -= 16;
                i0 = inp64[0];
                i1 = inp64[1];

                if (inl < 16)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                CVMX_MT_AES_DEC_CBC0(i0);
                CVMX_MT_AES_DEC_CBC1(i1);
           }
        }

        CVMX_MF_AES_RESULT(r0, 0);
        CVMX_MF_AES_RESULT(r1, 1);
        outp64[-2] = r0;
        outp64[-1] = r1;
    }
    /* remainder */
    if (inl > 0) {
        uint64_t in64[2] = { 0, 0 };
        XMEMCPY(in64, inp64, inl);
        CVMX_MT_AES_DEC_CBC0(in64[0]);
        CVMX_MT_AES_DEC_CBC1(in64[1]);
        CVMX_MF_AES_RESULT(r0, 0);
        CVMX_MF_AES_RESULT(r1, 1);
        outp64[0] = r0;
        outp64[1] = r1;
    }

    CVMX_MF_AES_IV(iv[0], 0);
    CVMX_MF_AES_IV(iv[1], 1);

    return 0;
}
#endif /* HAVE_AES_CBC */


#ifdef HAVE_AESGCM

/* The output registers need to be set in clobbered  mode, so as to indicate
   compiler about not sharing the same input and output registers */
#define CVM_AES_RD_RESULT_WR_DATA(in1, in2, out1, out2) asm volatile\
                                             (".set noreorder    \n" \
                                               "dmfc2 %[r1],0x0100\n" \
                                               "dmfc2 %[r2],0x0101\n" \
                                               "dmtc2 %[r3],0x010a\n" \
                                               "dmtc2 %[r4],0x310b\n" \
                                               ".set reorder      \n" \
                                               : [r1] "=&d"(in1) , [r2] "=&d"(in2) \
                                               : [r3] "d"(out1),  [r4] "d"(out2) )

// cur_aes_ctx is used to identify the last context that used the core
aes_gcm_ctx_t *cur_aes_ctx;

void GHASH_restore(uint16_t polynomial, void *multiplier)
{
    // Init Galois multiplier
    CVMX_MT_GFM_POLY((uint64_t) polynomial);

    // Init multiplier
    if (multiplier) {
        uint64_t *poly =(uint64_t *) multiplier;
        CVMX_MT_GFM_MUL(poly[0], 0);
        CVMX_MT_GFM_MUL(poly[1], 1);
    }
    return;
}

static inline void GHASH_init(uint16_t polynomial, void *multiplier)
{
    GHASH_restore(polynomial, multiplier);

    // Multiply by 0 to clear result
    CVMX_MT_GFM_RESINP(0, 0);
    CVMX_MT_GFM_RESINP(0, 1);
    return;
}

static inline void GHASH_update(uint64_t *data)
{
    // Feed data to the hash
    CVMX_MT_GFM_XOR0(data[0]);
    CVMX_MT_GFM_XORMUL1(data[1]);
    return;
}

static inline void GHASH_finish(uint64_t alen, uint64_t clen, void *res)
{
    block16_t *result =(block16_t *) res;

    // Feed lengths into the hash
    CVMX_MT_GFM_XOR0(alen);
    CVMX_MT_GFM_XORMUL1(clen);

    // Read the result(note stalls here until MPY is finished)
    CVMX_MF_GFM_RESINP(result->val64[0], 0);
    CVMX_MF_GFM_RESINP(result->val64[1], 1);
    return;
}

int AES_GCM_init_key(uint8_t *key, uint32_t keylen, aes_gcm_ctx_t *aes_ctx)
{
    uint64_t *kptr =(uint64_t *)key;

    if (!aes_ctx || !key) {
        return AES_GCM_INVALID_CTX;
    }

    XMEMSET(aes_ctx, 0, sizeof(aes_gcm_ctx_t));

    // Init key
    switch (keylen) {
        case 256:
            aes_ctx->K.val64[3] = kptr[3];
            CVMX_MT_AES_KEY(kptr[3], 3);
        case 192:
            aes_ctx->K.val64[2] = kptr[2];
            CVMX_MT_AES_KEY(kptr[2], 2);
        case 128:
            aes_ctx->K.val64[0] = kptr[0];
            aes_ctx->K.val64[1] = kptr[1];
            CVMX_MT_AES_KEY(kptr[1], 1);
            CVMX_MT_AES_KEY(kptr[0], 0);
            break;
        default:
            return AES_GCM_INVALID_KEYLENGTH;
    }

    aes_ctx->keylen = keylen / 64;
    CVMX_MT_AES_KEYLENGTH(aes_ctx->keylen - 1);

    // Run key schedule and get H
    CVMX_MT_AES_ENC0(0);
    CVMX_MT_AES_ENC1(0);

    CVMX_MF_AES_RESULT(aes_ctx->H.val64[0], 0);
    CVMX_MF_AES_RESULT(aes_ctx->H.val64[1], 1);

    cur_aes_ctx = aes_ctx;
    aes_ctx->done |= AES_GCM_KEY_DONE;

    // Done
    return AES_GCM_SUCCESS;
}

int AES_GCM_set_key(aes_gcm_ctx_t *aes_ctx)
{
    // Init key
    CVMX_MT_AES_KEY(aes_ctx->K.val64[3], 3);
    CVMX_MT_AES_KEY(aes_ctx->K.val64[2], 2);
    CVMX_MT_AES_KEY(aes_ctx->K.val64[1], 1);
    CVMX_MT_AES_KEY(aes_ctx->K.val64[0], 0);

    CVMX_MT_AES_KEYLENGTH(aes_ctx->keylen - 1);
    return 0;
}

int AES_GCM_set_iv(uint8_t* iv, uint32_t ivlen, aes_gcm_ctx_t* aes_ctx)
{
    int i;
    block16_t *ivb_ptr =(block16_t *) iv;

    if (!(aes_ctx->done & AES_GCM_KEY_DONE))
        return AES_GCM_KEY_NOT_SET;

    // Generate Y_0 as follows:
    //
    //          / IV || 0^31 || 1
    //   Y_0 = |
    //          \ GHASH(H,{},IV)

    if (ivlen ==(96 / 8)) {
        // Y_O = IV || 0^31 || 1
        aes_ctx->Y_i.val64[0] = ivb_ptr->val64[0];
        aes_ctx->Y_i.val32[2] = ivb_ptr->val32[2];
        aes_ctx->Y_i.val32[3] = 1;
    }
    else {
        int len = ivlen;
        block16_t last_block;

        // Init GHASH
        GHASH_init(0xe100, &aes_ctx->H.val64[0]);

        // Run GHASH for blocks 1 .. n-1
        for (i = 0; i <(len - 16); i += 16) {
            GHASH_update((uint64_t *) ivb_ptr);
            ivb_ptr++;
        }

        len = len - i;

        // Run GHASH for the last block
        last_block.val64[0] = 0;
        last_block.val64[1] = 0;
        for (i = 0; i < len; i++) {
            last_block.val8[i] = ivb_ptr->val8[i];
        }

        GHASH_update(last_block.val64);

        // Finish GHASH
        GHASH_finish(0, ivlen * 8, &aes_ctx->Y_i.val64[0]);
    }

    aes_ctx->Y_0 = aes_ctx->Y_i.val32[3];

    // Y_1
    aes_ctx->Y_i.val32[3]++;

    GHASH_init(0xe100, &aes_ctx->H.val64[0]);

    cur_aes_ctx = aes_ctx;
    aes_ctx->done |= AES_GCM_IV_DONE;

    return AES_GCM_SUCCESS;
}

int AES_GCM_set_aad(uint8_t *ain, uint32_t alen, aes_gcm_ctx_t *aes_ctx)
{
    int len, i;
    block16_t *iptr;
    block16_t input;

    // Authentication data is optional.
    // alen is 0, implies that there is no auth data.
    if (!alen) {
        goto end;
    }

    if (!(aes_ctx->done & AES_GCM_IV_DONE)) {
        return AES_GCM_IV_NOT_SET;
    }

    if (cur_aes_ctx != aes_ctx) {
        // Set iv from context
        GHASH_restore(0xe100, &aes_ctx->H.val64[0]);
    }

    iptr =(block16_t *) ain;
    len = alen;

    // Run GHASH for auth blocks 1 .. n-1
    for (i = 0; i <(len - 16); i += 16) {
        // Read auth data block
        CVMX_LOADUNA_INT64(input.val64[0], iptr, 0);
        CVMX_LOADUNA_INT64(input.val64[1], iptr++, 8);

        // GHASH Update
        CVMX_MT_GFM_XOR0(input.val64[0]);
        CVMX_MT_GFM_XORMUL1(input.val64[1]);
    }

    len = alen - i;

    // GHASH Update for the last auth block
    input.val64[0] = 0;
    input.val64[1] = 0;
    for (i = 0; i < len; i++) {
        input.val8[i] = iptr->val8[i];
    }

    CVMX_MT_GFM_XOR0(input.val64[0]);
    CVMX_MT_GFM_XORMUL1(input.val64[1]);

    if (!(aes_ctx->done & AES_GCM_SINGLE)) {
        // Store the hash calculated up to this point in context
        CVMX_MF_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MF_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }

end:

    if (!(aes_ctx->done & AES_GCM_SINGLE)) {
        // Set key from context
        AES_GCM_set_key(aes_ctx);

        // Set iv from context
        GHASH_restore(0xe100, &aes_ctx->H.val64[0]);

        // Load the HASH into register
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }
    cur_aes_ctx = aes_ctx;
    aes_ctx->done |= AES_GCM_AAD_DONE;
    return AES_GCM_SUCCESS;
}

/**
 *
 * @param *pin pointer to plain-text data(to be encrypted)
 * @param plen size of plain-text data in bytes
 * @param *out pointer to encrypted data(output)
 * @param *aes_ctx pointer AES-GCM context
 *
 */
int AES_GCM_ctx_encrypt(uint8_t* pin, uint32_t plen,
  uint8_t* out, aes_gcm_ctx_t* aes_ctx)
{
    int len, i;
    block16_t *iptr, *optr;
    block16_t input, result, mask;

    if (!(aes_ctx->done & AES_GCM_IV_DONE))
        return AES_GCM_IV_NOT_SET;

    // Pre-fetch first cache line
    CVMX_PREFETCH0(pin);

    if (cur_aes_ctx != aes_ctx) {
        // Set key from context
        AES_GCM_set_key(aes_ctx);

        // Set iv from context
        GHASH_restore(0xe100, &aes_ctx->H.val64[0]);

        // Load the HASH into register
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }

    // Start encrypting 2nd counter block
    //(to be used to XOR the first input data block)
    CVMX_MT_AES_ENC0(aes_ctx->Y_i.val64[0]);
    CVMX_MT_AES_ENC1(aes_ctx->Y_i.val64[1]);

    // =================
    // encrypt-auth loop
    // =================
    iptr =(block16_t *) pin;
    optr =(block16_t *) out;
    len = plen;

    if (len < 16)
        goto encrypt_loop_done;

    do {
        // Pre-fetch next cache-line
        CVMX_PREFETCH128(iptr);

        // Update remaining length
        len -= 16;

        // Increment counter value
        aes_ctx->Y_i.val32[3]++;

        // Read input data block
        CVMX_LOADUNA_INT64(input.val64[0], iptr, 0);
        CVMX_LOADUNA_INT64(input.val64[1], iptr++, 8);

        // Read previous result & start encrypting next counter block
        CVM_AES_RD_RESULT_WR_DATA(result.val64[0], result.val64[1],
            aes_ctx->Y_i.val64[0], aes_ctx->Y_i.val64[1]);

        // XOR input with AES result
        result.val64[0] ^= input.val64[0];
        result.val64[1] ^= input.val64[1];

        // Feed XOR result to GHASH
        CVMX_MT_GFM_XOR0(result.val64[0]);
        CVMX_MT_GFM_XORMUL1(result.val64[1]);

        // Write output
        CVMX_STOREUNA_INT64(result.val64[0], optr, 0);
        CVMX_STOREUNA_INT64(result.val64[1], optr++, 8);
    } while(len >= 16);

    // ====================
    // encrypt-auth trailer
    // ====================
encrypt_loop_done:

    if (len == 0) {
        if (!(aes_ctx->done & AES_GCM_SINGLE)) {
            // Store the hash calculated up to this point in context
            CVMX_MF_GFM_RESINP(aes_ctx->E.val64[0], 0);
            CVMX_MF_GFM_RESINP(aes_ctx->E.val64[1], 1);
        }
        cur_aes_ctx = aes_ctx;

        return AES_GCM_SUCCESS;
    }
    //  goto encrypt_done;

    mask.val64[0] = 0;
    mask.val64[1] = 0;

    // Get last input block
    for (i = 0; i < len; i++) {
        input.val8[i] = iptr->val8[i];
        mask.val8[i] = 0xff;
    }

    // Read last AES result
    CVMX_MF_AES_RESULT(result.val64[0], 0);
    CVMX_MF_AES_RESULT(result.val64[1], 1);

    // XOR input with last AES result
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Mask last XOR result
    result.val64[0] &= mask.val64[0];
    result.val64[1] &= mask.val64[1];

    // Feed last XOR result to GHASH
    CVMX_MT_GFM_XOR0(result.val64[0]);
    CVMX_MT_GFM_XORMUL1(result.val64[1]);

    if (!(aes_ctx->done & AES_GCM_SINGLE)) {
        // Store the hash calculated up to this point in context
        CVMX_MF_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MF_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }

    cur_aes_ctx = aes_ctx;

    // Write out last result
    for (i = 0; i < len; i++)
    optr->val8[i] = result.val8[i];
    return AES_GCM_SUCCESS;
}

/*AES_GCM_ctx_final*/
/**
 *
 * @param plen size of plain-text data in bytes
 * @param alen size of auth-only data in bytes
 * @param *tag pointer to 16-byte tag value(output)
 * @param *aes_ctx pointer AES-GCM context
 *
 */

int AES_GCM_ctx_final(uint32_t plen, uint32_t alen, uint8_t *tag, aes_gcm_ctx_t *aes_ctx)
{
    block16_t input, result;
    uint32_t Y_t;

    // Restore 1st counter value
    Y_t = aes_ctx->Y_i.val32[3];
    aes_ctx->Y_i.val32[3] = aes_ctx->Y_0;

    if (cur_aes_ctx != aes_ctx) {
        // Set key from context
        AES_GCM_set_key(aes_ctx);

        // Set iv from context
        GHASH_restore(0xe100, &aes_ctx->H.val64[0]);

        // Load the HASH into register
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }
    cur_aes_ctx = NULL;

    // Encrypt first counter block(Y_0)
    CVMX_MT_AES_ENC0(aes_ctx->Y_i.val64[0]);
    CVMX_MT_AES_ENC1(aes_ctx->Y_i.val64[1]);

    // Feed lengths to GHASH
    CVMX_MT_GFM_XOR0((uint64_t) alen * 8);
    CVMX_MT_GFM_XORMUL1((uint64_t) plen * 8);

    aes_ctx->Y_i.val32[3] = Y_t;

    // Read AES result
    CVMX_MF_AES_RESULT(input.val64[0], 0);
    CVMX_MF_AES_RESULT(input.val64[1], 1);

    // Read Galois result(GHASH_finish)
    //(have to stall here -- there is
    //  nothing else we can do)
    CVMX_MF_GFM_RESINP(result.val64[0], 0);
    CVMX_MF_GFM_RESINP(result.val64[1], 1);

    // Construct tag
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Write out tag
    CVMX_STOREUNA_INT64(result.val64[0], tag, 0);
    CVMX_STOREUNA_INT64(result.val64[1], tag, 8);

    return AES_GCM_SUCCESS;
}


/**
 *
 * @param *cin pointer to encrypted-text data(to be decrypted)
 * @param clen size of plain-text data in bytes
 * @param *out pointer to decrypted data(output)
 * @param *aes_ctx pointer AES-GCM context
 *
 */
int AES_GCM_ctx_decrypt(uint8_t * cin, uint32_t clen,
  uint8_t * out, aes_gcm_ctx_t * aes_ctx)
{
    int len, i;
    block16_t *iptr, *optr;
    block16_t input, result, mask;

    if (!(aes_ctx->done & AES_GCM_IV_DONE)) {
        return AES_GCM_IV_NOT_SET;
    }

    // Pre-fetch first cache line
    CVMX_PREFETCH0(cin);

    if (cur_aes_ctx != aes_ctx) {
        // Set key from context
        AES_GCM_set_key(aes_ctx);

        // Set iv from context
        GHASH_restore(0xe100, &aes_ctx->H.val64[0]);

        // Load the HASH into register
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MT_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }

    // Start encrypting block
    //(to be used to XOR the first input data block)
    CVMX_MT_AES_ENC0(aes_ctx->Y_i.val64[0]);
    CVMX_MT_AES_ENC1(aes_ctx->Y_i.val64[1]);

    // =================
    // decrypt-auth loop
    // =================
    iptr =(block16_t *) cin;
    optr =(block16_t *) out;
    len = clen;

    if (len < 16) {
        goto decrypt_loop_done;
    }

    do {
        // Pre-fetch next cache-line
        CVMX_PREFETCH128(iptr);

        // Update remaining length
        len -= 16;

        // Increment counter value
        aes_ctx->Y_i.val32[3]++;

        // Read input data block
        CVMX_LOADUNA_INT64(input.val64[0], iptr, 0);
        CVMX_LOADUNA_INT64(input.val64[1], iptr++, 8);

        // Read previous result & start encrypting next counter block
        CVM_AES_RD_RESULT_WR_DATA(result.val64[0], result.val64[1],
            aes_ctx->Y_i.val64[0], aes_ctx->Y_i.val64[1]);

        // Feed XOR result to GHASH
        CVMX_MT_GFM_XOR0(input.val64[0]);
        CVMX_MT_GFM_XORMUL1(input.val64[1]);

        // XOR input with AES result
        result.val64[0] ^= input.val64[0];
        result.val64[1] ^= input.val64[1];

        // Write output
        CVMX_STOREUNA_INT64(result.val64[0], optr, 0);
        CVMX_STOREUNA_INT64(result.val64[1], optr++, 8);
    } while (len >= 16);

    // ====================
    // decrypt-auth trailer
    // ====================
decrypt_loop_done:

    if (len == 0) {
        if (!(aes_ctx->done & AES_GCM_SINGLE)) {
            // Store the hash calculated up to this point in context
            CVMX_MF_GFM_RESINP(aes_ctx->E.val64[0], 0);
            CVMX_MF_GFM_RESINP(aes_ctx->E.val64[1], 1);
        }
        cur_aes_ctx = aes_ctx;
        return AES_GCM_SUCCESS;
    }
    // goto decrypt_done;

    mask.val64[0] = 0;
    mask.val64[1] = 0;

    input.val64[0] = 0;
    input.val64[1] = 0;

    // Get last input block
    for (i = 0; i < len; i++) {
        input.val8[i] = iptr->val8[i];
        mask.val8[i] = 0xff;
    }

    // Feed last XOR result to GHASH
    CVMX_MT_GFM_XOR0(input.val64[0]);
    CVMX_MT_GFM_XORMUL1(input.val64[1]);

    if (!(aes_ctx->done & AES_GCM_SINGLE)) {
        // Store the hash calculated up to this point in context
        CVMX_MF_GFM_RESINP(aes_ctx->E.val64[0], 0);
        CVMX_MF_GFM_RESINP(aes_ctx->E.val64[1], 1);
    }

    // Read last AES result
    CVMX_MF_AES_RESULT(result.val64[0], 0);
    CVMX_MF_AES_RESULT(result.val64[1], 1);

    // XOR input with last AES result
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Mask last XOR result
    result.val64[0] &= mask.val64[0];
    result.val64[1] &= mask.val64[1];

    cur_aes_ctx = aes_ctx;

    // Write out last result
    for (i = 0; i < len; i++) {
        optr->val8[i] = result.val8[i];
    }

    return AES_GCM_SUCCESS;
}

int AES_GCM_encrypt(uint8_t *key, uint32_t keylen, uint8_t *iv,
  uint32_t ivlen, uint8_t *ain, uint32_t alen, uint8_t *pin,
  uint32_t plen, uint8_t *out, uint8_t *tag)
{
    aes_gcm_ctx_t aes_ctx;
    int ret;

    ret = AES_GCM_init_key(key, keylen, &aes_ctx);
    if (ret)
        return ret;

    // This flag identifies whether it is a single call or multicall.
    // Kept this here to save some cycles in single call.
    aes_ctx.done |= AES_GCM_SINGLE;
    ret = AES_GCM_set_iv(iv, ivlen, &aes_ctx);
    if (ret)
        return ret;
    ret = AES_GCM_set_aad(ain, alen, &aes_ctx);
    if (ret)
        return ret;
    AES_GCM_ctx_encrypt(pin, plen, out, &aes_ctx);
    return AES_GCM_ctx_final(plen, alen, tag, &aes_ctx);
}

int AES_GCM_decrypt(uint8_t *key, uint32_t keylen, uint8_t *iv,
  uint32_t ivlen, uint8_t *ain, uint32_t alen, uint8_t *cin,
  uint32_t clen, uint8_t *out, uint8_t *tag)
{
    aes_gcm_ctx_t aes_ctx;
    int ret;

    ret = AES_GCM_init_key(key, keylen, &aes_ctx);
    if (ret)
        return ret;

    // This flag identifies whether it is a single call or multicall.
    // Kept this here to save some cycles in single call.
    aes_ctx.done |= AES_GCM_SINGLE;
    ret = AES_GCM_set_iv(iv, ivlen, &aes_ctx);
    if (ret)
        return ret;
    ret = AES_GCM_set_aad(ain, alen, &aes_ctx);
    if (ret)
        return ret;

    AES_GCM_ctx_decrypt(cin, clen, out, &aes_ctx);
    return AES_GCM_ctx_final(clen, alen, tag, &aes_ctx);
}

int AES_GMAC_ctx_tag(uint8_t *ain, uint32_t alen, uint8_t *tag,
                 aes_gcm_ctx_t *aes_ctx)
{
    block16_t *iptr;
    block16_t input, result;
    uint32_t len;
    int i;

    if (!(aes_ctx->done & AES_GCM_IV_DONE))
        return AES_GCM_IV_NOT_SET;

    /* set up AES key */
    AES_GCM_set_key(aes_ctx);

    GHASH_init(0xe100, &aes_ctx->H.val64[0]);

    if (alen == 0)
        goto auth_done;

    iptr =(block16_t *)ain;
    len = alen;

    // Run GHASH for auth blocks 1 .. n-1
    for (i = 0; i <(int)(len - 16); i += 16) {
        // Read auth data block
        CVMX_LOADUNA_INT64(input.val64[0], iptr, 0);
        CVMX_LOADUNA_INT64(input.val64[1], iptr++, 8);

        // GHASH Update
        CVMX_MT_GFM_XOR0(input.val64[0]);
        CVMX_MT_GFM_XORMUL1(input.val64[1]);
    }

    len = alen - i;

    // GHASH Update for the last auth block
    input.val64[0] = 0;
    input.val64[1] = 0;
    for (i = 0; i <(int)len; i++)
        input.val8[i] = iptr->val8[i];

    CVMX_MT_GFM_XOR0(input.val64[0]);
    CVMX_MT_GFM_XORMUL1(input.val64[1]);

auth_done:

    // Feed lengths to GHASH
    CVMX_MT_GFM_XOR0((uint64_t) alen * 8);
    CVMX_MT_GFM_XORMUL1((uint64_t) 0x0ull);

    aes_ctx->Y_i.val32[3] = aes_ctx->Y_0;

    // Encrypt first counter block(Y_0)
    CVMX_MT_AES_ENC0(aes_ctx->Y_i.val64[0]);
    CVMX_MT_AES_ENC1(aes_ctx->Y_i.val64[1]);

    CVMX_MF_GFM_RESINP(result.val64[0], 0);
    CVMX_MF_GFM_RESINP(result.val64[1], 1);

    // Read AES result
    CVMX_MF_AES_RESULT(input.val64[0], 0);
    CVMX_MF_AES_RESULT(input.val64[1], 1);

    // Construct tag
    result.val64[0] ^= input.val64[0];
    result.val64[1] ^= input.val64[1];

    // Write out tag
    CVMX_STOREUNA_INT64(result.val64[0], tag, 0);
    CVMX_STOREUNA_INT64(result.val64[1], tag, 8);

    return AES_GMAC_SUCCESS;
}

int AES_GMAC_tag(uint8_t *key, uint32_t keylen, uint8_t *iv, uint32_t ivlen,
             uint8_t *ain, uint32_t alen, uint8_t *tag)
{
    aes_gcm_ctx_t aes_ctx;
    int ret;

    ret = AES_GCM_init_key(key, keylen, &aes_ctx);
    if (ret)
        return ret;

    ret = AES_GCM_set_iv(iv, ivlen, &aes_ctx);
    if (ret)
        return ret;

    return AES_GMAC_ctx_tag(ain, alen, tag, &aes_ctx);
}

#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#endif /* HAVE_CAVIUM_OCTEON */
