#include "secure_boot.h"

/*
 * Provision this immutable value during the manufacturing build. Keeping the
 * default invalid is deliberate: accepting unsigned images would defeat secure
 * boot entirely.
 */
const uint8_t secure_boot_public_key[ECDSA_P256_PUBLIC_KEY_SIZE] = {0};
