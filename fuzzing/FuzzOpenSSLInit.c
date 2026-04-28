/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Shared one-shot init for libFuzzer targets. Linked into every fuzzer
 * via FUZZ_COMMON_SOURCES so a single LLVMFuzzerInitialize covers all
 * binaries.
 *
 * Responsibilities:
 *   1. Deterministic OpenSSL setup (skips environment-dependent config
 *      loading that trips MSan in unsanitized libcrypto).
 *   2. Seed the public<->private address mapping table with synthetic
 *      pairs. Without this mcount stays 0 forever in the fuzz process,
 *      which makes the loop body in map_addr_from_public_to_private /
 *      map_addr_from_private_to_public (and the addr_eq_no_port call
 *      it gates) unreachable. OSS-Fuzz introspector flags those as
 *      blockers; seeding two pairs (one v4, one v6) makes the loop
 *      body live for every fuzz iteration that decodes an address.
 */

#include <stddef.h>
#include <stdint.h>

#include <openssl/crypto.h>

#include "ns_turn_ioaddr.h"

static void seed_addr_mappings(void) {
  ioa_addr pub4 = {0};
  ioa_addr priv4 = {0};
  ioa_addr pub6 = {0};
  ioa_addr priv6 = {0};

  if (make_ioa_addr((const uint8_t *)"192.0.2.1", 0, &pub4) == 0 &&
      make_ioa_addr((const uint8_t *)"10.0.0.1", 0, &priv4) == 0) {
    ioa_addr_add_mapping(&pub4, &priv4);
  }

  if (make_ioa_addr((const uint8_t *)"2001:db8::1", 0, &pub6) == 0 &&
      make_ioa_addr((const uint8_t *)"fd00::1", 0, &priv6) == 0) {
    ioa_addr_add_mapping(&pub6, &priv6);
  }
}

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

  seed_addr_mappings();

  return 0;
}
