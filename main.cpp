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

#include "mbed.h"
#include "psa_initial_attestation_api.h"
#include "psa_attest_inject_key.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "entropy.h"
#include "entropy_poll.h"
#include "mbedtls/version.h"

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

#if !defined(MBEDTLS_PSA_CRYPTO_C) || (MBEDTLS_VERSION_NUMBER < 0x02130000)
int main(void)
{
    mbedtls_printf("Not all of the requirements are met:\n"
                   "  - MBEDTLS_PSA_CRYPTO_C\n"
                   "  - PSA Crypto API v1.0b3\n");
    return 0;
}
#else

#define PSA_ATTESTATION_PRIVATE_KEY_ID 17

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
    uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)];
    enum psa_attest_err_t attest_err = PSA_ATTEST_ERR_SUCCESS;
    uint32_t token_size;

    status = psa_crypto_init();
    ASSERT_STATUS(status, PSA_SUCCESS);
    status = psa_attestation_inject_key(NULL,
                                        0,
                                        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1),
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

int main(void)
{
    psa_key_handle_t handle;
    
    attestation_example();

    psa_open_key(PSA_ATTESTATION_PRIVATE_KEY_ID, &handle);
    psa_destroy_key(handle);
    mbedtls_psa_crypto_free();
    return 0;
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC &&
          MBEDTLS_CIPHER_MODE_CTR && MBEDTLS_CIPHER_MODE_WITH_PADDING */
