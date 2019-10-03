/* cavium_octeon.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
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

#ifndef _CAVIUM_OCTEON_H_
#define _CAVIUM_OCTEON_H_

#ifdef HAVE_CAVIUM_OCTEON

#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "cvmx.h"
#include "cvmx-asm.h"
#include "cvmx-key.h"
#include "cvmx-swap.h"


#ifndef NO_DES3
int Octeon_Des3_CbcEncrypt(Des3 *key, uint64_t *inp64, uint64_t *outp64, size_t inl);
int Octeon_Des3_CbcDecrypt(Des3 *key, uint64_t *inp64, uint64_t *outp64, size_t inl);
#endif /* !NO_DES3 */


#ifndef NO_AES

#ifdef WOLFSSL_AES_DIRECT
int Octeon_AesEcb_Encrypt(Aes *aes, const unsigned char *in, unsigned char *out);
int Octeon_AesEcb_Decrypt(Aes *aes, const unsigned char *in, unsigned char *out);
#endif

#ifdef HAVE_AES_CBC
int Octeon_AesCbc_Encrypt(Aes *aes, uint64_t *inp64, uint64_t *outp64, size_t inl);
int Octeon_AesCbc_Decrypt(Aes *aes, uint64_t *inp64, uint64_t *outp64, size_t inl);
#endif

#ifdef HAVE_AESGCM

typedef union {
    uint64_t val64[2];
    uint32_t val32[4];
    uint8_t  val8[16];
} block16_t;

typedef union {
    uint64_t val64[4];
    uint32_t val32[8];
    uint8_t  val8[32];
} block32_t;

typedef struct aes_gcm_ctx_type {
    // Counter value Y_i (128 bits)
    block16_t Y_i;

    // AES Key (128, 192, or 256 bits)
    block32_t K;

    // H (128 bits)
    block16_t H;

    // Calculated HASH
    block16_t E;

    // (used at the end to XOR with GHASH output to form auth tag)
    uint32_t Y_0;

    // AES key length
    uint32_t keylen;

    // state
    uint32_t done;
} aes_gcm_ctx_t;

// context flags (bit fields)
#define AES_GCM_SINGLE   0x1
#define AES_GCM_KEY_DONE 0x2
#define AES_GCM_IV_DONE  0x4
#define AES_GCM_AAD_DONE 0x8

// Return codes
#define AES_GCM_SUCCESS              0
#define AES_GCM_INVALID_KEYLENGTH   -1
#define AES_GCM_INVALID_CTX         -2
#define AES_GCM_IV_NOT_SET          -3
#define AES_GCM_KEY_NOT_SET         -4
#define AES_GCM_NOT_SUPPORTED       -5
#define AES_GCM_AAD_NOT_SET         -6
#define AES_GMAC_SUCCESS             0

/**
* AES GCM Initialization of the key
* @param key pointer to Key of size keylen bits (Input)
* @param keylen Length of the key in bits (Input)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*        This is an opaque pointer to the user (Input)
* @return AES_GCM_SUCCESS (0)
*         AES_GCM_INVALID_KEYLENGTH (-1)
*/
int AES_GCM_init_key (uint8_t *key, uint32_t keylen,
  aes_gcm_ctx_t *aes_ctx);

/**
* AES GCM Set the IV
* @param iv pointer to "iv" of size "ivlen" bytes (Input)
* @param ivlen Length of the iv in bytes (Input)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*        This is an opaque pointer to the user (Input)
* @return AES_GCM_SUCCESS (0)
*         AES_GCM_INVALID_CTX (-2)
*         AES_GCM_KEY_NOT_SET (-4)
*/
int AES_GCM_set_iv (uint8_t *iv, uint32_t ivlen,
  aes_gcm_ctx_t *aes_ctx);

/**
* AES GCM Set AAD
* @param ain pointer to Authentication data of size "alen" bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*      This is an opaque pointer to the user (Input)
* @return AES_GCM_SUCCESS (0)
*      AES_GCM_IV_NOT_SET (-5)
*/
int AES_GCM_set_aad (uint8_t *ain, uint32_t alen,
        aes_gcm_ctx_t *aes_ctx);

/**
* AES GCM Encryption + Authentication operation
*          (Multiple calls for same key)
*          This encrypts plain input and authenticates the input
*          authentication data. One or both of these inputs can
*          be given together.
* @param pin pointer to Plain input of size "plen" bytes (Input)
* @param plen Length of the Plain input in bytes (Input)
* @param out pointer to Ciphered output of size "plen" bytes (Output)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*        This is an opaque pointer to the user (Input)
* @return AES_GCM_SUCCESS (0)
*         AES_GCM_INVALID_CTX (-2)
*         AES_GCM_IV_NOT_SET  (-3)
*         AES_GCM_KEY_NOT_SET (-4)
*/
int AES_GCM_ctx_encrypt (uint8_t *pin, uint32_t plen,
  uint8_t *out, aes_gcm_ctx_t *aes_ctx);

/**
* AES GCM final MAC calulation
* @param plen Length of the Plain input in bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param tag Pointer to 16 bytes of generated authentication tag (Output)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*/
int AES_GCM_ctx_final(uint32_t plen, uint32_t alen, uint8_t *tag,
  aes_gcm_ctx_t *aes_ctx);


/**
* AES GCM Decryption + Authentication operation
*          (Multiple calls for same key)
*          This decrypts ciphered input and authenticates the input
*          authentication data. One or both of these inputs can
*          be given together.
* @param cin pointer to Ciphered input of size "clen" bytes (Input)
* @param clen Length of the Ciphered input in bytes (Input)
* @param out pointer to Plain output of size "clen" bytes (Output)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*        This is an opaque pointer to the user (Input)
* @return AES_GCM_SUCCESS (0)
*         AES_GCM_INVALID_KEYLENGTH (-1)
*         AES_GCM_INVALID_CTX (-2)
*         AES_GCM_IV_NOT_SET  (-3)
*         AES_GCM_KEY_NOT_SET (-4)
*/
int AES_GCM_ctx_decrypt(uint8_t *cin, uint32_t clen,
  uint8_t *out, aes_gcm_ctx_t *aes_ctx);

/**
* AES GCM Encryption + Authentication operation
*          This encrypts plain input and authenticates the input
*          authentication data. One or both of these inputs can
*          be given together.
* @param key pointer to Key of size keylen bits (Input)
* @param keylen Length of the key in bits (Input)
* @param iv pointer to "iv" of size "ivlen" bytes (Input)
* @param ivlen Length of the iv in bytes (Input)
* @param ain pointer to Authentication data of size "alen" bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param pin pointer to Plain input of size "plen" bytes (Input)
* @param plen Length of the Plain input in bytes (Input)
* @param out pointer to Ciphered output of size "plen" bytes (Output)
* @param tag Pointer to 16 bytes of generated authentication tag (Output)
* @return AES_GCM_SUCCESS (0)
*         AES_GCM_INVALID_KEYLENGTH (-1)
*         AES_GCM_INVALID_CTX (-2)
*         AES_GCM_IV_NOT_SET  (-3)
*         AES_GCM_KEY_NOT_SET (-4)
*/

int AES_GCM_encrypt(uint8_t *key, uint32_t keylen, uint8_t *iv,
  uint32_t ivlen, uint8_t *ain, uint32_t alen, uint8_t *pin,
  uint32_t plen, uint8_t *out, uint8_t *tag);
/**
* AES GCM Decryption + Authentication operation
*          This decrypts ciphered input and authenticates the input
*          authentication data. One or both of these inputs can
*          be given together.
* @param key pointer to Key of size keylen bits (Input)
* @param keylen Length of the key in bits (Input)
* @param iv pointer to "iv" of size "ivlen" bytes (Input)
* @param ivlen Length of the iv in bytes (Input)
* @param cin pointer to Ciphered input of size "clen" bytes (Input)
* @param clen Length of the Ciphered input in bytes (Input)
* @param ain pointer to Authentication data of size "alen" bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param out pointer to Plain output of size "clen" bytes (Output)
* @param tag Pointer to 16 bytes of generated authentication tag (Output)
* @return AES_GCM_SUCCESS (0)
*         AES_GCM_INVALID_KEYLENGTH (-1)
*         AES_GCM_INVALID_CTX (-2)
*         AES_GCM_IV_NOT_SET  (-3)
*         AES_GCM_KEY_NOT_SET (-4)
*/

int AES_GCM_decrypt(uint8_t *key, uint32_t keylen, uint8_t *iv,
  uint32_t ivlen, uint8_t *ain, uint32_t alen, uint8_t *cin,
  uint32_t clen, uint8_t *out, uint8_t *tag);

/**
* AES GMAC Authentication operation
*          This authenticates the authentication data.
* @param key pointer to Key of size keylen bits (Input)
* @param keylen Length of the key in bits (Input)
* @param iv pointer to "iv" of size "ivlen" bytes (Input)
* @param ivlen Length of the iv in bytes (Input)
* @param ain pointer to Authentication data of size "alen" bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param tag Pointer to 16 bytes of generated authentication tag (Output)
* @return AES_GMAC_SUCCESS (0)
*         AES_GCM_INVALID_KEYLENGTH (-1)
*         AES_GCM_INVALID_CTX (-2)
*         AES_GCM_IV_NOT_SET  (-3)
*         AES_GCM_KEY_NOT_SET (-4)
*/
int AES_GMAC_tag(uint8_t *key, uint32_t keylen, uint8_t *iv, uint32_t ivlen,
           uint8_t *ain, uint32_t alen, uint8_t *tag);

/**
* AES GMAC Authentication operation
*          (Multiple calls for same key)
* @param ain pointer to Authentication data of size "alen" bytes (Input)
* @param alen Length of the Authentication data in bytes (Input)
* @param tag Pointer to 16 bytes of generated authentication tag (Output)
* @param aes_ctx pointer to aes_gcm_ctx_t structure.
*        This is an opaque pointer to the user (Input)
* @return AES_GMAC_SUCCESS (0)
*         AES_GCM_IV_NOT_SET  (-3)
*/
int AES_GMAC_ctx_tag(uint8_t *ain, uint32_t alen, uint8_t *tag,
               aes_gcm_ctx_t *aes_ctx);

void GHASH_restore (uint16_t polynomial, void *multiplier);

int AES_GCM_set_key (aes_gcm_ctx_t *aes_ctx);

#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#endif /* HAVE_CAVIUM_OCTEON */
#endif /* _CAVIUM_OCTEON_H_ */
