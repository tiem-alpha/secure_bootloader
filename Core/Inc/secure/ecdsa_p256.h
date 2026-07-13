/**
 * @file ecdsa_p256.h
 * @brief Minimal ECDSA P-256 sign/verify API.
 *
 * @author nguyentiem
 *
 * This module implements ECDSA over NIST P-256, also known as secp256r1 or
 * prime256v1.
 *
 * Public API:
 * - ecdsa_p256_generate_keypair(): create a private/public key pair.
 * - ecdsa_p256_sign_digest(): sign a 32-byte message digest.
 * - ecdsa_p256_verify_digest(): verify a signature over a 32-byte digest.
 *
 * Hashing is deliberately left to the caller. For normal use, pass
 * SHA-256(message) as digest32.
 *
 * Buffer format:
 * - Private key: 32-byte big-endian scalar d, where 1 <= d < n.
 * - Public key: 64-byte raw uncompressed coordinates, X || Y, each 32-byte
 *   big-endian. The 0x04 uncompressed-point prefix is not included.
 * - Digest: 32-byte message digest. Usually SHA-256(message).
 * - Signature: 64-byte raw IEEE P1363 signature, r || s, each 32-byte
 *   big-endian. DER encoding is not used.
 *
 * Memory policy:
 * - Caller owns all input/output buffers.
 * - No heap allocation is used.
 * - No large precomputed RAM tables are used.
 */
#ifndef MY_CRYPTO_ECDSA_P256_H
#define MY_CRYPTO_ECDSA_P256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECDSA_P256_SIZE 32u

/** Size in bytes of a raw P-256 public key: X || Y. */
#define ECDSA_P256_PUBLIC_KEY_SIZE 64u

/** Size in bytes of a raw ECDSA P-256 signature: r || s. */
#define ECDSA_P256_SIGNATURE_SIZE 64u

/**
 * @brief Random byte generator callback.
 *
 * @param[in,out] ctx User-provided RNG context. May be NULL if the callback
 *                    does not need context.
 * @param[out] out Output buffer to fill with random bytes.
 * @param[in] out_len Number of random bytes requested.
 *
 * @return 0 on success.
 * @return Non-zero on RNG failure.
 *
 * Security requirement: for ECDSA signing, this callback must produce a fresh,
 * unpredictable nonce. Reusing the same nonce with the same private key can
 * expose the private key.
 */
typedef int (*ecdsa_p256_random_func)(void *ctx, uint8_t *out, size_t out_len);

/**
 * @brief Generate an ECDSA P-256 private/public key pair.
 *
 * @param[out] private_key 32-byte big-endian private scalar d.
 * @param[out] public_key 64-byte raw public key, X || Y.
 * @param[in] rng Random byte generator callback.
 * @param[in,out] rng_ctx User context passed to @p rng. May be NULL if the RNG
 *                        callback supports NULL context.
 *
 * @return 0 on success.
 * @return -1 if an argument is NULL, the RNG fails, or public-key derivation
 *         fails.
 */
int ecdsa_p256_generate_keypair(
    uint8_t private_key[ECDSA_P256_SIZE],
    uint8_t public_key[ECDSA_P256_PUBLIC_KEY_SIZE],
    ecdsa_p256_random_func rng,
    void *rng_ctx);

/**
 * @brief Sign a 32-byte digest with ECDSA P-256.
 *
 * The output signature uses raw IEEE P1363 format:
 *
 *     signature = r || s
 *
 * where r and s are 32-byte big-endian integers.
 *
 * @param[in] private_key 32-byte big-endian private scalar d. Must satisfy
 *                        1 <= d < n.
 * @param[in] digest32 32-byte digest to sign. Usually SHA-256(message).
 * @param[out] signature 64-byte output buffer for r || s.
 * @param[in] rng Random byte generator callback used to generate the ECDSA
 *                nonce k.
 * @param[in,out] rng_ctx User context passed to @p rng. May be NULL if the RNG
 *                        callback supports NULL context.
 *
 * @return 0 on success.
 * @return -1 if an argument is NULL, the private key is invalid, the RNG fails,
 *         or signing fails.
 *
 * @warning The RNG must never repeat a nonce for the same private key. Nonce
 *          reuse can reveal the private key.
 */
int ecdsa_p256_sign_digest(const uint8_t private_key[ECDSA_P256_SIZE],
                           const uint8_t digest32[ECDSA_P256_SIZE],
                           uint8_t signature[ECDSA_P256_SIGNATURE_SIZE],
                           ecdsa_p256_random_func rng,
                           void *rng_ctx);

/**
 * @brief Verify an ECDSA P-256 signature over a 32-byte digest.
 *
 * @param[in] public_key 64-byte raw public key, X || Y. X and Y are 32-byte
 *                       big-endian field elements. The point must be on the
 *                       P-256 curve.
 * @param[in] digest32 32-byte digest that was signed. Usually
 *                     SHA-256(message).
 * @param[in] signature 64-byte raw IEEE P1363 signature, r || s. r and s are
 *                      32-byte big-endian integers.
 *
 * @return 0 if the signature is valid.
 * @return -1 if an argument is NULL, the public key is invalid, the signature
 *         encoding/range is invalid, or verification fails.
 */
int ecdsa_p256_verify_digest(
    const uint8_t public_key[ECDSA_P256_PUBLIC_KEY_SIZE],
    const uint8_t digest32[ECDSA_P256_SIZE],
    const uint8_t signature[ECDSA_P256_SIGNATURE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
