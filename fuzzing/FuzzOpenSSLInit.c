/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Shared OpenSSL initialization for libFuzzer targets.
 */

#include <stddef.h>

#include <openssl/crypto.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

#if defined(OPENSSL_INIT_NO_LOAD_CONFIG) && !defined(LIBRESSL_VERSION_NUMBER)
  /*
   * Keep fuzzing deterministic and avoid MSan reports from OpenSSL's
   * environment-dependent config file loading in unsanitized libcrypto.
   */
  OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
#endif

  return 0;
}
