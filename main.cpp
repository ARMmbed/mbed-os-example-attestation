/*
 * Copyright (c) 2018, Arm Limited and affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "psa_initial_attestation_api.h"
#include "psa_attest_inject_key.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "entropy.h"
#include "entropy_poll.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif

#define ASSERT_STATUS(actual, expected)                                       \
    do                                                                        \
    {                                                                         \
        if((actual) != (expected))                                            \
        {                                                                     \
            mbedtls_printf( "\tassertion failed at %s:%d - "                  \
                            "actual:%" PRId32 "expected:%" PRId32 "\n",     \
                            __FILE__, __LINE__,                               \
                            (psa_status_t) actual, (psa_status_t) expected ); \
            goto exit;                                                        \
        }                                                                     \
    } while (0)

#if !defined(MBEDTLS_PSA_CRYPTO_C)
int main(void)
{
    mbedtls_printf("Not all of the required options are defined:\n"
                   "  - MBEDTLS_PSA_CRYPTO_C\n");
    return 0;
}
#else

#define PSA_ATTESTATION_PRIVATE_KEY_ID 17

static const uint8_t private_key_data[] = {
    0x49, 0xc9, 0xa8, 0xc1, 0x8c, 0x4b, 0x88, 0x56,
    0x38, 0xc4, 0x31, 0xcf, 0x1d, 0xf1, 0xc9, 0x94,
    0x13, 0x16, 0x09, 0xb5, 0x80, 0xd4, 0xfd, 0x43,
    0xa0, 0xca, 0xb1, 0x7d, 0xb2, 0xf1, 0x3e, 0xee
};

static const uint8_t public_key_data[] = {
    0x04, 0x77, 0x72, 0x65, 0x6f, 0x81, 0x4b, 0x39,
    0x92, 0x79, 0xd5, 0xe1, 0xf1, 0x78, 0x1f, 0xac,
    0x6f, 0x09, 0x9a, 0x3c, 0x5c, 0xa1, 0xb0, 0xe3,
    0x53, 0x51, 0x83, 0x4b, 0x08, 0xb6, 0x5e, 0x0b,
    0x57, 0x25, 0x90, 0xcd, 0xaf, 0x8f, 0x76, 0x93,
    0x61, 0xbc, 0xf3, 0x4a, 0xcf, 0xc1, 0x1e, 0x5e,
    0x07, 0x4e, 0x84, 0x26, 0xbd, 0xde, 0x04, 0xbe,
    0x6e, 0x65, 0x39, 0x45, 0x44, 0x96, 0x17, 0xde,
    0x45
};

#define TEST_TOKEN_SIZE (0x200)
#define TEST_CHALLENGE_OBJ_SIZE (32u)

#define CHALLENGE_FOR_TEST  0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, \
                            0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, \
                            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, \
                            0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF

static uint8_t token_buffer[TEST_TOKEN_SIZE];
static uint8_t challenge_buffer[TEST_CHALLENGE_OBJ_SIZE] = {CHALLENGE_FOR_TEST};


static psa_status_t check_initial_attestation_get_token()
{
    psa_status_t status = PSA_SUCCESS;
    size_t exported_length;
    uint8_t exported[sizeof(public_key_data)];
    enum psa_attest_err_t attest_err = PSA_ATTEST_ERR_SUCCESS;
    uint32_t token_size;

    status = psa_crypto_init();
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = psa_attestation_inject_key(private_key_data,
                                        sizeof(private_key_data),
                                        PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1),
                                        exported,
                                        sizeof(exported),
                                        &exported_length);

    ASSERT_STATUS(status, PSA_SUCCESS);

    attest_err = psa_initial_attest_get_token_size(TEST_CHALLENGE_OBJ_SIZE,
                                                   &token_size);

    ASSERT_STATUS(attest_err, PSA_ATTEST_ERR_SUCCESS);

    attest_err = psa_initial_attest_get_token(challenge_buffer,
                                              TEST_CHALLENGE_OBJ_SIZE,
                                              token_buffer,
                                              &token_size);

    ASSERT_STATUS(attest_err, PSA_ATTEST_ERR_SUCCESS);

exit:
    if(attest_err != PSA_ATTEST_ERR_SUCCESS)
        return attest_err;
    return status;
}

static void attestation_example(void)
{
    psa_status_t status;

    mbedtls_printf("Get attestation token:\n");
    status = check_initial_attestation_get_token();
    if (status == PSA_SUCCESS) {
        mbedtls_printf("\tsuccess!\n");
    }
}

static void fake_set_initial_nvseed(void)
{
    /* This function, fake_set_initial_nvseed(), is useless on platforms that
     * have already been manufactured correctly. This function demonstrates
     * what a factory tool may do in order to manufacture a device that does
     * not have its own source of entropy. */

    /* mbedtls_psa_inject_entropy() is always present, but calls to it will
     * always fail unless the PSA Secure Processing Element (SPE) is configured
     * with both MBEDTLS_ENTROPY_NV_SEED and MBEDTLS_PSA_HAS_ITS_IO by the
     * SPE's Mbed TLS configuration system. */
    uint8_t seed[MBEDTLS_ENTROPY_MAX_SEED_SIZE];

    /* Calculate a fake seed for injecting. A real factory application would
     * inject true entropy for use as the initial NV Seed. */
    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = i;
    }

    int status = mbedtls_psa_inject_entropy(seed, sizeof(seed));
    if (status) {
        /* The device may already have an NV Seed injected, or another error
         * may have happened during injection. */
        mbedtls_printf("warning (%d) - this attempt at entropy injection"
                       " failed\n", status);
    }
}

int main(void)
{
    const psa_key_id_t key_id = PSA_ATTESTATION_PRIVATE_KEY_ID;
    psa_key_handle_t handle = 0;

    fake_set_initial_nvseed();
    
    attestation_example();

    psa_open_key(PSA_KEY_LIFETIME_PERSISTENT, key_id, &handle);
    psa_destroy_key(handle);
    mbedtls_psa_crypto_free();
    return 0;
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC &&
          MBEDTLS_CIPHER_MODE_CTR && MBEDTLS_CIPHER_MODE_WITH_PADDING */
