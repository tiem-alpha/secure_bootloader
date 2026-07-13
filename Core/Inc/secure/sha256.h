/**
 * @file sha256.h
 * @brief Small SHA-256 API used by secure boot verification.
 */
#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <stddef.h>
#include <stdint.h>

/** SHA-256 digest size in bytes. */
#define SHA256_DIGEST_SIZE 32U
/** SHA-256 compression block size in bytes. */
#define SHA256_BLOCK_SIZE  64U

/** Streaming SHA-256 context. */
typedef struct {
    /** Internal SHA-256 chaining state. */
    uint32_t state[8];
    /** Total number of message bytes processed. */
    uint64_t total_size;
    /** Number of bytes currently stored in buffer. */
    size_t buffer_size;
    /** Partial block buffer. */
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_context_t;

/**
 * @brief Initialize a SHA-256 streaming context.
 *
 * @param[out] context Context to initialize. NULL is accepted and ignored.
 *
 * @post @p context is ready for zero or more @ref sha256_update calls.
 */
void sha256_init(sha256_context_t *context);

/**
 * @brief Feed message bytes into a SHA-256 streaming context.
 *
 * @param[in,out] context Initialized SHA-256 context.
 * @param[in] data Input message bytes. May be NULL only when @p size is 0.
 * @param[in] size Number of input bytes.
 *
 * @post Updates internal hash state and buffered partial block bytes.
 */
void sha256_update(sha256_context_t *context, const void *data, size_t size);

/**
 * @brief Finalize a SHA-256 context and write the digest.
 *
 * @param[in,out] context Initialized SHA-256 context.
 * @param[out] digest Output buffer for @ref SHA256_DIGEST_SIZE bytes.
 *
 * @post The context memory is securely cleared after the digest is produced.
 */
void sha256_final(sha256_context_t *context, uint8_t digest[SHA256_DIGEST_SIZE]);

/**
 * @brief Compute SHA-256 over one contiguous input buffer.
 *
 * @param[in] data Input message bytes. May be NULL only when @p size is 0.
 * @param[in] size Number of input bytes.
 * @param[out] digest Output buffer for @ref SHA256_DIGEST_SIZE bytes.
 */
void sha256_compute(const void *data, size_t size, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif
