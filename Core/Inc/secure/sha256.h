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

/** Initialize a SHA-256 context. */
void sha256_init(sha256_context_t *context);
/** Feed message bytes into a SHA-256 context. */
void sha256_update(sha256_context_t *context, const void *data, size_t size);
/** Finalize a SHA-256 context and write a 32-byte digest. */
void sha256_final(sha256_context_t *context, uint8_t digest[SHA256_DIGEST_SIZE]);
/** Compute SHA-256 over one contiguous input buffer. */
void sha256_compute(const void *data, size_t size, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif
