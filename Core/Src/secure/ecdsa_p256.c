#include "ecdsa_p256.h"

#include <string.h>

/*
 * Standalone ECDSA P-256 implementation.
 *
 * The original version used affine points and repeated modular inversions
 * during scalar multiplication. This version uses 8x32-bit limbs, Montgomery
 * multiplication, and Jacobian points. That matches Cortex-M3 class MCUs much
 * better: point multiplication does one field inversion at the end instead of
 * one inversion per point add/double.
 */

#define NLIMBS 8
#define NBITS  256

typedef struct { uint32_t v[NLIMBS]; } u256;
typedef struct { u256 x; u256 y; } affine_point;
typedef struct { u256 x; u256 y; u256 z; int infinity; } jacobian_point;

static const u256 P256_P = {{ 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U,
                              0x00000000U, 0x00000000U, 0x00000001U, 0xffffffffU }};
static const u256 P256_N = {{ 0xfc632551U, 0xf3b9cac2U, 0xa7179e84U, 0xbce6faadU,
                              0xffffffffU, 0xffffffffU, 0x00000000U, 0xffffffffU }};

static const u256 P256_P_R2 = {{ 0x00000003U, 0x00000000U, 0xffffffffU, 0xfffffffbU,
                                 0xfffffffeU, 0xffffffffU, 0xfffffffdU, 0x00000004U }};
static const u256 P256_N_R2 = {{ 0xbe79eea2U, 0x83244c95U, 0x49bd6fa6U, 0x4699799cU,
                                 0x2b6bec59U, 0x2845b239U, 0xf3d95620U, 0x66e12d94U }};
static const u256 P256_P_ONE = {{ 0x00000001U, 0x00000000U, 0x00000000U, 0xffffffffU,
                                  0xffffffffU, 0xffffffffU, 0xfffffffeU, 0x00000000U }};
static const u256 P256_N_ONE = {{ 0x039cdaafU, 0x0c46353dU, 0x58e8617bU, 0x43190552U,
                                  0x00000000U, 0x00000000U, 0xffffffffU, 0x00000000U }};
static const u256 P256_P_THREE = {{ 0x00000003U, 0x00000000U, 0x00000000U, 0xfffffffdU,
                                    0xffffffffU, 0xffffffffU, 0xfffffffcU, 0x00000002U }};
static const u256 P256_B_MONT = {{ 0x29c4bddfU, 0xd89cdf62U, 0x78843090U, 0xacf005cdU,
                                   0xf7212ed6U, 0xe5a220abU, 0x04874834U, 0xdc30061dU }};

static const affine_point P256_G_MONT = {
    {{ 0x18a9143cU, 0x79e730d4U, 0x5fedb601U, 0x75ba95fcU,
       0x77622510U, 0x79fb732bU, 0xa53755c6U, 0x18905f76U }},
    {{ 0xce95560aU, 0xddf25357U, 0xba19e45cU, 0x8b4ab8e4U,
       0xdd21f325U, 0xd2e88688U, 0x25885d85U, 0x8571ff18U }}
};

static const affine_point P256_G_TABLE_MONT[16] = {
    { {{ 0 }}, {{ 0 }} },
    { {{ 0x18a9143cU, 0x79e730d4U, 0x5fedb601U, 0x75ba95fcU, 0x77622510U, 0x79fb732bU, 0xa53755c6U, 0x18905f76U }}, {{ 0xce95560aU, 0xddf25357U, 0xba19e45cU, 0x8b4ab8e4U, 0xdd21f325U, 0xd2e88688U, 0x25885d85U, 0x8571ff18U }} },
    { {{ 0x10ddd64dU, 0x850046d4U, 0xa433827dU, 0xaa6ae3c1U, 0x8d1490d9U, 0x73220503U, 0x3dcf3a3bU, 0xf6bb32e4U }}, {{ 0x61bee1a5U, 0x2f3648d3U, 0xeb236ff8U, 0x152cd7cbU, 0x92042dbeU, 0x19a8fb0eU, 0x0a5b8a3bU, 0x78c57751U }} },
    { {{ 0x4eebc127U, 0xffac3f90U, 0x087d81fbU, 0xb027f84aU, 0x87cbbc98U, 0x66ad77ddU, 0xb6ff747eU, 0x26936a3fU }}, {{ 0xc983a7ebU, 0xb04c5c1fU, 0x0861fe1aU, 0x583e47adU, 0x1a2ee98eU, 0x78820831U, 0xe587cc07U, 0xd5f06a29U }} },
    { {{ 0x46918dccU, 0x74b0b50dU, 0xc623c173U, 0x4650a6edU, 0xe8100af2U, 0x0cdaacacU, 0x41b0176bU, 0x577362f5U }}, {{ 0xe4cbaba6U, 0x2d96f24cU, 0xfad6f447U, 0x17628471U, 0xe5ddd22eU, 0x6b6c36deU, 0x4c5ab863U, 0x84b14c39U }} },
    { {{ 0xc45c61f5U, 0xbe1b8aaeU, 0x94b9537dU, 0x90ec649aU, 0xd076c20cU, 0x941cb5aaU, 0x890523c8U, 0xc9079605U }}, {{ 0xe7ba4f10U, 0xeb309b4aU, 0xe5eb882bU, 0x73c568efU, 0x7e7a1f68U, 0x3540a987U, 0x2dd1e916U, 0x73a076bbU }} },
    { {{ 0x3e77664aU, 0x40394737U, 0x346cee3eU, 0x55ae744fU, 0x5b17a3adU, 0xd50a961aU, 0x54213673U, 0x13074b59U }}, {{ 0xd377e44bU, 0x93d36220U, 0xadff14b5U, 0x299c2b53U, 0xef639f11U, 0xf424d44cU, 0x4a07f75fU, 0xa4c9916dU }} },
    { {{ 0xa0173b4fU, 0x0746354eU, 0xd23c00f7U, 0x2bd20213U, 0x0c23bb08U, 0xf43eaab5U, 0xc3123e03U, 0x13ba5119U }}, {{ 0x3f5b9d4dU, 0x2847d030U, 0x5da67bddU, 0x6742f2f2U, 0x77c94195U, 0xef933bdcU, 0x6e240867U, 0xeaedd915U }} },
    { {{ 0x9499a78fU, 0x27f14cd1U, 0x6f9b3455U, 0x462ab5c5U, 0xf02cfc6bU, 0x8f90f02aU, 0xb265230dU, 0xb763891eU }}, {{ 0x532d4977U, 0xf59da3a9U, 0xcf9eba15U, 0x21e3327dU, 0xbe60bbf0U, 0x123c7b84U, 0x7706df76U, 0x56ec12f2U }} },
    { {{ 0x264e20e8U, 0x75c96e8fU, 0x59a7a841U, 0xabe6bfedU, 0x44c8eb00U, 0x2cc09c04U, 0xf0c4e16bU, 0xe05b3080U }}, {{ 0xa45f3314U, 0x1eb7777aU, 0xce5d45e3U, 0x56af7bedU, 0x88b12f1aU, 0x2b6e019aU, 0xfd835f9bU, 0x086659cdU }} },
    { {{ 0x9dc21ec8U, 0x2c18dbd1U, 0x0fcf8139U, 0x98f9868aU, 0x48250b49U, 0x737d2cd6U, 0x24b3428fU, 0xcc61c947U }}, {{ 0x80dd9e76U, 0x0c2b4078U, 0x383fbe08U, 0xc43a8991U, 0x779be5d2U, 0x5f7d2d65U, 0xeb3b4ab5U, 0x78719a54U }} },
    { {{ 0x6245e404U, 0xea7d260aU, 0x6e7fdfe0U, 0x9de40795U, 0x8dac1ab5U, 0x1ff3a415U, 0x649c9073U, 0x3e7090f1U }}, {{ 0x2b944e88U, 0x1a768561U, 0xe57f61c8U, 0x250f939eU, 0x1ead643dU, 0x0c0daa89U, 0xe125b88eU, 0x68930023U }} },
    { {{ 0xd2697768U, 0x04b71aa7U, 0xca345a33U, 0xabdedef5U, 0xee37385eU, 0x2409d29dU, 0xcb83e156U, 0x4ee1df77U }}, {{ 0x1cbb5b43U, 0x0cac12d9U, 0xca895637U, 0x170ed2f6U, 0x8ade6d66U, 0x28228cfaU, 0x53238acaU, 0x7ff57c95U }} },
    { {{ 0x4b2ed709U, 0xccc42563U, 0x856fd30dU, 0x0e356769U, 0x559e9811U, 0xbcbcd43fU, 0x5395b759U, 0x738477acU }}, {{ 0xc00ee17fU, 0x35752b90U, 0x742ed2e3U, 0x68748390U, 0xbd1f5bc1U, 0x7cd06422U, 0xc9e7b797U, 0xfbc08769U }} },
    { {{ 0xb0cf664aU, 0xa242a35bU, 0x7f9707e3U, 0x126e48f7U, 0xc6832660U, 0x1717bf54U, 0xfd12c72eU, 0xfaae7332U }}, {{ 0x995d586bU, 0x27b52db7U, 0x832237c2U, 0xbe29569eU, 0x2a65e7dbU, 0xe8e4193eU, 0x2eaa1bbbU, 0x152706dcU }} },
    { {{ 0xbc60055bU, 0x72bcd8b7U, 0x56e27e4bU, 0x03cc23eeU, 0xe4819370U, 0xee337424U, 0x0ad3da09U, 0xe2aa0e43U }}, {{ 0x6383c45dU, 0x40b8524fU, 0x42a41b25U, 0xd7663554U, 0x778a4797U, 0x64efa6deU, 0x7079adf4U, 0x2042170aU }} },
};

/**
 * @brief Clear sensitive memory through a volatile pointer.
 *
 * @param[out] p Memory region to clear.
 * @param[in] n Number of bytes to clear.
 */
static void memzero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n-- != 0u) *v++ = 0;
}

/**
 * @brief Test whether a 256-bit little-limb integer is zero.
 *
 * @param[in] a Integer to test.
 *
 * @return 1 when all limbs are zero, 0 otherwise.
 */
static int u256_is_zero(const u256 *a)
{
    uint32_t acc = 0;
    int i;
    for (i = 0; i < NLIMBS; i++) acc |= a->v[i];
    return acc == 0u;
}

/**
 * @brief Compare two 256-bit little-limb integers.
 *
 * @param[in] a Left operand.
 * @param[in] b Right operand.
 *
 * @return 1 when @p a > @p b.
 * @return 0 when @p a == @p b.
 * @return -1 when @p a < @p b.
 */
static int u256_cmp(const u256 *a, const u256 *b)
{
    int i;
    for (i = NLIMBS - 1; i >= 0; i--) {
        if (a->v[i] > b->v[i]) return 1;
        if (a->v[i] < b->v[i]) return -1;
    }
    return 0;
}

/**
 * @brief Subtract two 256-bit integers without modular reduction.
 *
 * @param[out] r Difference output, `a - b` modulo 2^256.
 * @param[in] a Minuend.
 * @param[in] b Subtrahend.
 *
 * @return Final borrow bit, 1 when @p a < @p b.
 */
static uint32_t u256_sub_raw(u256 *r, const u256 *a, const u256 *b)
{
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < NLIMBS; i++) {
        uint64_t av = a->v[i];
        uint64_t bv = (uint64_t)b->v[i] + borrow;
        r->v[i] = (uint32_t)(av - bv);
        borrow = (av < bv) ? 1u : 0u;
    }
    return (uint32_t)borrow;
}

/**
 * @brief Add two 256-bit integers without modular reduction.
 *
 * @param[out] r Sum output, `a + b` modulo 2^256.
 * @param[in] a First addend.
 * @param[in] b Second addend.
 *
 * @return Final carry bit.
 */
static uint32_t u256_add_raw(u256 *r, const u256 *a, const u256 *b)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < NLIMBS; i++) {
        uint64_t sum = (uint64_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

/**
 * @brief Add two integers modulo @p m.
 *
 * @param[out] r Modular sum output.
 * @param[in] a First operand, expected in range `[0, m)`.
 * @param[in] b Second operand, expected in range `[0, m)`.
 * @param[in] m Modulus.
 */
static void mod_add(u256 *r, const u256 *a, const u256 *b, const u256 *m)
{
    u256 t;
    uint32_t carry = u256_add_raw(&t, a, b);
    if (carry != 0u || u256_cmp(&t, m) >= 0) {
        (void)u256_sub_raw(&t, &t, m);
    }
    *r = t;
}

/**
 * @brief Subtract two integers modulo @p m.
 *
 * @param[out] r Modular difference output.
 * @param[in] a First operand, expected in range `[0, m)`.
 * @param[in] b Second operand, expected in range `[0, m)`.
 * @param[in] m Modulus.
 */
static void mod_sub(u256 *r, const u256 *a, const u256 *b, const u256 *m)
{
    if (u256_sub_raw(r, a, b) != 0u) {
        (void)u256_add_raw(r, r, m);
    }
}

/**
 * @brief Decode a 32-byte big-endian integer into little-limb form.
 *
 * @param[out] r Decoded integer.
 * @param[in] in 32-byte big-endian input.
 */
static void u256_from_be(u256 *r, const uint8_t in[32])
{
    int i;
    for (i = 0; i < NLIMBS; i++) {
        size_t off = (size_t)(NLIMBS - 1 - i) * 4u;
        r->v[i] = ((uint32_t)in[off] << 24) | ((uint32_t)in[off + 1u] << 16) |
                  ((uint32_t)in[off + 2u] << 8) | in[off + 3u];
    }
}

/**
 * @brief Encode a little-limb integer as 32-byte big-endian bytes.
 *
 * @param[out] out 32-byte output buffer.
 * @param[in] a Integer to encode.
 */
static void u256_to_be(uint8_t out[32], const u256 *a)
{
    int i;
    for (i = 0; i < NLIMBS; i++) {
        uint32_t limb = a->v[NLIMBS - 1 - i];
        out[(size_t)i * 4u] = (uint8_t)(limb >> 24);
        out[(size_t)i * 4u + 1u] = (uint8_t)(limb >> 16);
        out[(size_t)i * 4u + 2u] = (uint8_t)(limb >> 8);
        out[(size_t)i * 4u + 3u] = (uint8_t)limb;
    }
}

/**
 * @brief Read one bit from a 256-bit integer.
 *
 * @param[in] a Integer to inspect.
 * @param[in] bit Bit index in range 0..255.
 *
 * @return 0 or 1.
 */
static int u256_bit(const u256 *a, int bit)
{
    return (int)((a->v[bit >> 5] >> (bit & 31)) & 1u);
}

/**
 * @brief Montgomery multiply two residues modulo @p m.
 *
 * @param[out] r Product residue output.
 * @param[in] a First Montgomery-domain operand.
 * @param[in] b Second Montgomery-domain operand.
 * @param[in] m Modulus.
 * @param[in] n0inv Montgomery reduction constant `-m[0]^-1 mod 2^32`.
 */
static void mont_mul(u256 *r, const u256 *a, const u256 *b,
                     const u256 *m, uint32_t n0inv)
{
    uint32_t t[NLIMBS * 2u + 1u];
    int i;
    int j;

    memset(t, 0, sizeof(t));

    for (i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (j = 0; j < NLIMBS; j++) {
            uint64_t uv = (uint64_t)a->v[j] * b->v[i] + t[i + j] + carry;
            t[i + j] = (uint32_t)uv;
            carry = uv >> 32;
        }
        for (j = i + NLIMBS; carry != 0u; j++) {
            uint64_t uv = (uint64_t)t[j] + carry;
            t[j] = (uint32_t)uv;
            carry = uv >> 32;
        }

        {
            uint32_t q = t[i] * n0inv;
            carry = 0;
            for (j = 0; j < NLIMBS; j++) {
                uint64_t uv = (uint64_t)q * m->v[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)uv;
                carry = uv >> 32;
            }
            for (j = i + NLIMBS; carry != 0u; j++) {
                uint64_t uv = (uint64_t)t[j] + carry;
                t[j] = (uint32_t)uv;
                carry = uv >> 32;
            }
        }
    }

    for (i = 0; i < NLIMBS; i++) r->v[i] = t[i + NLIMBS];
    if (t[NLIMBS * 2u] != 0u || u256_cmp(r, m) >= 0) {
        (void)u256_sub_raw(r, r, m);
    }
}

/**
 * @brief Convert a normal integer into Montgomery domain.
 *
 * @param[out] r Montgomery-domain output.
 * @param[in] a Normal-domain input.
 * @param[in] m Modulus.
 * @param[in] r2 Precomputed `R^2 mod m`.
 * @param[in] n0inv Montgomery reduction constant.
 */
static void mont_from(u256 *r, const u256 *a, const u256 *m,
                      const u256 *r2, uint32_t n0inv)
{
    mont_mul(r, a, r2, m, n0inv);
}

/**
 * @brief Convert a Montgomery-domain integer back to normal domain.
 *
 * @param[out] r Normal-domain output.
 * @param[in] a Montgomery-domain input.
 * @param[in] m Modulus.
 * @param[in] n0inv Montgomery reduction constant.
 */
static void mont_to(u256 *r, const u256 *a, const u256 *m, uint32_t n0inv)
{
    static const u256 one = {{ 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u }};
    mont_mul(r, a, &one, m, n0inv);
}

/**
 * @brief Multiply two P-256 field elements in Montgomery domain.
 *
 * @param[out] r Field product output.
 * @param[in] a First field operand.
 * @param[in] b Second field operand.
 */
static void field_mul(u256 *r, const u256 *a, const u256 *b)
{
    mont_mul(r, a, b, &P256_P, 0x00000001U);
}

/**
 * @brief Square one P-256 field element in Montgomery domain.
 *
 * @param[out] r Field square output.
 * @param[in] a Field operand.
 */
static void field_sqr(u256 *r, const u256 *a) { field_mul(r, a, a); }

/**
 * @brief Add two P-256 field elements in Montgomery domain.
 *
 * @param[out] r Field sum output.
 * @param[in] a First field operand.
 * @param[in] b Second field operand.
 */
static void field_add(u256 *r, const u256 *a, const u256 *b) { mod_add(r, a, b, &P256_P); }

/**
 * @brief Subtract two P-256 field elements in Montgomery domain.
 *
 * @param[out] r Field difference output.
 * @param[in] a First field operand.
 * @param[in] b Second field operand.
 */
static void field_sub(u256 *r, const u256 *a, const u256 *b) { mod_sub(r, a, b, &P256_P); }

/**
 * @brief Multiply two P-256 group-order scalars in Montgomery domain.
 *
 * @param[out] r Scalar product output.
 * @param[in] a First scalar operand.
 * @param[in] b Second scalar operand.
 */
static void scalar_mul(u256 *r, const u256 *a, const u256 *b)
{
    mont_mul(r, a, b, &P256_N, 0xee00bc4fU);
}

/**
 * @brief Add two P-256 group-order scalars in Montgomery domain.
 *
 * @param[out] r Scalar sum output.
 * @param[in] a First scalar operand.
 * @param[in] b Second scalar operand.
 */
static void scalar_add(u256 *r, const u256 *a, const u256 *b) { mod_add(r, a, b, &P256_N); }

/**
 * @brief Raise a Montgomery-domain value to an exponent modulo @p m.
 *
 * @param[out] r Power result in Montgomery domain.
 * @param[in] a Base in Montgomery domain.
 * @param[in] e 256-bit exponent in normal little-limb form.
 * @param[in] m Modulus.
 * @param[in] n0inv Montgomery reduction constant.
 * @param[in] one_mont Montgomery representation of 1 for @p m.
 */
static void mont_pow(u256 *r, const u256 *a, const u256 *e,
                     const u256 *m, uint32_t n0inv, const u256 *one_mont)
{
    u256 result = *one_mont;
    u256 base = *a;
    int i;
    for (i = NBITS - 1; i >= 0; i--) {
        mont_mul(&result, &result, &result, m, n0inv);
        if (u256_bit(e, i)) {
            mont_mul(&result, &result, &base, m, n0inv);
        }
    }
    *r = result;
}

/**
 * @brief Compute multiplicative inverse in the P-256 field.
 *
 * @param[out] r Inverse output in Montgomery domain.
 * @param[in] a Field element in Montgomery domain.
 *
 * @return 0 on success.
 * @return -1 when @p a is zero.
 */
static int field_inv(u256 *r, const u256 *a)
{
    static const u256 p_minus_2 = {{ 0xfffffffdU, 0xffffffffU, 0xffffffffU, 0x00000000U,
                                     0x00000000U, 0x00000000U, 0x00000001U, 0xffffffffU }};
    if (u256_is_zero(a)) return -1;
    mont_pow(r, a, &p_minus_2, &P256_P, 0x00000001U, &P256_P_ONE);
    return 0;
}

/**
 * @brief Compute multiplicative inverse modulo the P-256 group order.
 *
 * @param[out] r Inverse output in Montgomery domain.
 * @param[in] a Scalar in Montgomery domain.
 *
 * @return 0 on success.
 * @return -1 when @p a is zero.
 */
static int scalar_inv(u256 *r, const u256 *a)
{
    static const u256 n_minus_2 = {{ 0xfc63254fU, 0xf3b9cac2U, 0xa7179e84U, 0xbce6faadU,
                                     0xffffffffU, 0xffffffffU, 0x00000000U, 0xffffffffU }};
    if (u256_is_zero(a)) return -1;
    mont_pow(r, a, &n_minus_2, &P256_N, 0xee00bc4fU, &P256_N_ONE);
    return 0;
}

/**
 * @brief Set a Jacobian point to the point at infinity.
 *
 * @param[out] p Point to reset.
 */
static void point_set_infinity(jacobian_point *p)
{
    memset(p, 0, sizeof(*p));
    p->infinity = 1;
}

/**
 * @brief Double a Jacobian P-256 point.
 *
 * @param[out] r Doubled point output.
 * @param[in] p Input point in Jacobian coordinates.
 *
 * @post @p r is set to infinity when @p p is infinity or has zero Y.
 */
static void point_double(jacobian_point *r, const jacobian_point *p)
{
    u256 delta;
    u256 gamma;
    u256 beta;
    u256 alpha;
    u256 t1;
    u256 t2;
    u256 t3;
    u256 x3;
    u256 y3;
    u256 z3;

    if (p->infinity || u256_is_zero(&p->y)) {
        point_set_infinity(r);
        return;
    }

    field_sqr(&delta, &p->z);
    field_sqr(&gamma, &p->y);
    field_mul(&beta, &p->x, &gamma);

    field_sub(&t1, &p->x, &delta);
    field_add(&t2, &p->x, &delta);
    field_mul(&alpha, &t1, &t2);
    field_add(&t1, &alpha, &alpha);
    field_add(&alpha, &t1, &alpha);

    field_sqr(&x3, &alpha);
    field_add(&t1, &beta, &beta);
    field_add(&t1, &t1, &t1);
    field_add(&t2, &t1, &t1);
    field_sub(&x3, &x3, &t2);

    field_add(&t3, &p->y, &p->z);
    field_sqr(&z3, &t3);
    field_sub(&z3, &z3, &gamma);
    field_sub(&z3, &z3, &delta);

    field_sub(&t1, &t1, &x3);
    field_mul(&y3, &alpha, &t1);
    field_sqr(&t2, &gamma);
    field_add(&t2, &t2, &t2);
    field_add(&t2, &t2, &t2);
    field_add(&t2, &t2, &t2);
    field_sub(&y3, &y3, &t2);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->infinity = 0;
}

/**
 * @brief Add an affine point to a Jacobian point.
 *
 * @param[out] r Sum output in Jacobian coordinates.
 * @param[in] p Jacobian input point.
 * @param[in] q Affine input point in Montgomery field representation.
 *
 * @post Handles point-at-infinity and inverse-point cases.
 */
static void point_add_mixed(jacobian_point *r, const jacobian_point *p,
                            const affine_point *q)
{
    u256 z1z1;
    u256 u2;
    u256 s2;
    u256 h;
    u256 i;
    u256 j;
    u256 rr;
    u256 v;
    u256 t1;
    u256 t2;
    u256 x3;
    u256 y3;
    u256 z3;

    if (p->infinity) {
        r->x = q->x;
        r->y = q->y;
        r->z = P256_P_ONE;
        r->infinity = 0;
        return;
    }

    field_sqr(&z1z1, &p->z);
    field_mul(&u2, &q->x, &z1z1);
    field_mul(&s2, &p->z, &z1z1);
    field_mul(&s2, &s2, &q->y);
    field_sub(&h, &u2, &p->x);
    field_sub(&rr, &s2, &p->y);

    if (u256_is_zero(&h)) {
        if (u256_is_zero(&rr)) {
            point_double(r, p);
        } else {
            point_set_infinity(r);
        }
        return;
    }

    field_add(&i, &h, &h);
    field_sqr(&i, &i);
    field_mul(&j, &h, &i);
    field_add(&rr, &rr, &rr);
    field_mul(&v, &p->x, &i);

    field_sqr(&x3, &rr);
    field_sub(&x3, &x3, &j);
    field_sub(&x3, &x3, &v);
    field_sub(&x3, &x3, &v);

    field_sub(&t1, &v, &x3);
    field_mul(&y3, &rr, &t1);
    field_mul(&t2, &p->y, &j);
    field_add(&t2, &t2, &t2);
    field_sub(&y3, &y3, &t2);

    field_add(&z3, &p->z, &h);
    field_sqr(&z3, &z3);
    field_sub(&z3, &z3, &z1z1);
    field_sqr(&t1, &h);
    field_sub(&z3, &z3, &t1);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->infinity = 0;
}

/**
 * @brief Convert a Jacobian point to affine coordinates.
 *
 * @param[out] r Affine point output.
 * @param[in] p Jacobian point input.
 *
 * @return 0 on success.
 * @return -1 when @p p is infinity or Z cannot be inverted.
 */
static int point_to_affine(affine_point *r, const jacobian_point *p)
{
    u256 zinv;
    u256 z2;
    u256 z3;

    if (p->infinity || field_inv(&zinv, &p->z) != 0) return -1;
    field_sqr(&z2, &zinv);
    field_mul(&z3, &z2, &zinv);
    field_mul(&r->x, &p->x, &z2);
    field_mul(&r->y, &p->y, &z3);
    return 0;
}

/**
 * @brief Multiply the P-256 base point by a scalar.
 *
 * @param[out] r Affine public point output in Montgomery field representation.
 * @param[in] k Scalar multiplier in normal little-limb form.
 *
 * @return 0 on success.
 * @return -1 when @p k is zero or conversion to affine fails.
 */
static int point_mul_base(affine_point *r, const u256 *k)
{
    jacobian_point acc;
    int i;

    if (u256_is_zero(k)) return -1;
    point_set_infinity(&acc);
    for (i = (NBITS / 4) - 1; i >= 0; i--) {
        uint32_t nibble;
        int j;
        for (j = 0; j < 4; j++) {
            point_double(&acc, &acc);
        }
        nibble = (k->v[i >> 3] >> ((i & 7) * 4)) & 0x0fU;
        if (nibble != 0u) {
            point_add_mixed(&acc, &acc, &P256_G_TABLE_MONT[nibble]);
        }
    }
    return point_to_affine(r, &acc);
}

/**
 * @brief Add two affine P-256 points.
 *
 * @param[out] r Affine sum output.
 * @param[in] a First affine input point.
 * @param[in] b Second affine input point.
 *
 * @return 0 on success.
 * @return -1 when the resulting point cannot be converted to affine.
 */
static int point_add_affine(affine_point *r, const affine_point *a,
                            const affine_point *b)
{
    jacobian_point p;
    p.x = a->x;
    p.y = a->y;
    p.z = P256_P_ONE;
    p.infinity = 0;
    point_add_mixed(&p, &p, b);
    return point_to_affine(r, &p);
}

/**
 * @brief Compute `u1 * G + u2 * Q` for ECDSA verification.
 *
 * @param[out] r Affine result point.
 * @param[in] u1 Base-point scalar.
 * @param[in] q Public key point in affine Montgomery representation.
 * @param[in] u2 Public-key scalar.
 *
 * @return 0 on success.
 * @return -1 when the result cannot be converted to affine.
 */
static int point_double_mul(affine_point *r, const u256 *u1,
                            const affine_point *q, const u256 *u2)
{
    affine_point g_plus_q;
    jacobian_point acc;
    int have_g_plus_q;
    int i;

    have_g_plus_q = point_add_affine(&g_plus_q, &P256_G_MONT, q) == 0;
    point_set_infinity(&acc);

    for (i = NBITS - 1; i >= 0; i--) {
        int idx;
        point_double(&acc, &acc);
        idx = u256_bit(u1, i) | (u256_bit(u2, i) << 1);
        if (idx == 1) {
            point_add_mixed(&acc, &acc, &P256_G_MONT);
        } else if (idx == 2) {
            point_add_mixed(&acc, &acc, q);
        } else if (idx == 3) {
            if (have_g_plus_q) {
                point_add_mixed(&acc, &acc, &g_plus_q);
            } else {
                point_add_mixed(&acc, &acc, &P256_G_MONT);
                point_add_mixed(&acc, &acc, q);
            }
        }
    }

    return point_to_affine(r, &acc);
}

/**
 * @brief Check whether an affine point satisfies the P-256 curve equation.
 *
 * @param[in] p Affine point in Montgomery field representation.
 *
 * @return 1 when the point is on the curve.
 * @return 0 otherwise.
 */
static int point_is_on_curve(const affine_point *p)
{
    u256 y2;
    u256 x2;
    u256 x3;
    u256 rhs;
    u256 three_x;

    field_sqr(&y2, &p->y);
    field_sqr(&x2, &p->x);
    field_mul(&x3, &x2, &p->x);
    field_mul(&three_x, &P256_P_THREE, &p->x);
    field_sub(&rhs, &x3, &three_x);
    field_add(&rhs, &rhs, &P256_B_MONT);
    return u256_cmp(&y2, &rhs) == 0;
}

/**
 * @brief Parse and validate a private scalar.
 *
 * @param[out] d Parsed scalar in normal little-limb form.
 * @param[in] private_key 32-byte big-endian private key.
 *
 * @return 1 when `1 <= d < n`.
 * @return 0 when the scalar is out of range.
 */
static int parse_private(u256 *d, const uint8_t private_key[32])
{
    u256_from_be(d, private_key);
    return !u256_is_zero(d) && u256_cmp(d, &P256_N) < 0;
}

/**
 * @brief Draw a random non-zero scalar smaller than the group order.
 *
 * @param[out] k Random scalar output.
 * @param[in] rng Random byte callback.
 * @param[in,out] rng_ctx User context passed to @p rng.
 *
 * @return 0 on success.
 * @return -1 when the RNG fails or no valid scalar is drawn in 64 attempts.
 *
 * @post Temporary random bytes are cleared before return.
 */
static int random_scalar(u256 *k, ecdsa_p256_random_func rng, void *rng_ctx)
{
    uint8_t buf[32];
    int tries;
    if (rng == NULL) return -1;
    for (tries = 0; tries < 64; tries++) {
        if (rng(rng_ctx, buf, sizeof(buf)) != 0) return -1;
        u256_from_be(k, buf);
        if (!u256_is_zero(k) && u256_cmp(k, &P256_N) < 0) {
            memzero(buf, sizeof(buf));
            return 0;
        }
    }
    memzero(buf, sizeof(buf));
    return -1;
}

/** @copydoc ecdsa_p256_generate_keypair */
int ecdsa_p256_generate_keypair(uint8_t private_key[32],
                                uint8_t public_key[64],
                                ecdsa_p256_random_func rng,
                                void *rng_ctx)
{
    u256 d;
    affine_point q;
    u256 x;
    u256 y;

    if (private_key == NULL || public_key == NULL) return -1;
    if (random_scalar(&d, rng, rng_ctx) != 0) return -1;

    if (point_mul_base(&q, &d) != 0) {
        memzero(&d, sizeof(d));
        return -1;
    }

    mont_to(&x, &q.x, &P256_P, 0x00000001U);
    mont_to(&y, &q.y, &P256_P, 0x00000001U);
    u256_to_be(private_key, &d);
    u256_to_be(public_key, &x);
    u256_to_be(public_key + 32, &y);
    memzero(&d, sizeof(d));
    return 0;
}

/** @copydoc ecdsa_p256_sign_digest */
int ecdsa_p256_sign_digest(const uint8_t private_key[32],
                           const uint8_t digest32[32],
                           uint8_t signature[64],
                           ecdsa_p256_random_func rng,
                           void *rng_ctx)
{
    u256 d;
    u256 d_m;
    u256 z;
    u256 z_m;
    u256 k;
    u256 k_m;
    u256 kinv_m;
    u256 r;
    u256 r_m;
    u256 s_m;
    u256 tmp_m;
    affine_point kg;
    u256 rx;
    int tries;

    if (private_key == NULL || digest32 == NULL || signature == NULL ||
        !parse_private(&d, private_key)) {
        return -1;
    }

    u256_from_be(&z, digest32);
    if (u256_cmp(&z, &P256_N) >= 0) (void)u256_sub_raw(&z, &z, &P256_N);
    mont_from(&d_m, &d, &P256_N, &P256_N_R2, 0xee00bc4fU);
    mont_from(&z_m, &z, &P256_N, &P256_N_R2, 0xee00bc4fU);

    for (tries = 0; tries < 64; tries++) {
        if (random_scalar(&k, rng, rng_ctx) != 0) goto err;
        if (point_mul_base(&kg, &k) != 0) goto err;
        mont_to(&rx, &kg.x, &P256_P, 0x00000001U);
        r = rx;
        if (u256_cmp(&r, &P256_N) >= 0) (void)u256_sub_raw(&r, &r, &P256_N);
        if (u256_is_zero(&r)) continue;

        mont_from(&k_m, &k, &P256_N, &P256_N_R2, 0xee00bc4fU);
        if (scalar_inv(&kinv_m, &k_m) != 0) goto err;
        mont_from(&r_m, &r, &P256_N, &P256_N_R2, 0xee00bc4fU);
        scalar_mul(&tmp_m, &r_m, &d_m);
        scalar_add(&tmp_m, &tmp_m, &z_m);
        scalar_mul(&s_m, &kinv_m, &tmp_m);
        mont_to(&tmp_m, &s_m, &P256_N, 0xee00bc4fU);
        if (u256_is_zero(&tmp_m)) continue;

        u256_to_be(signature, &r);
        u256_to_be(signature + 32, &tmp_m);
        memzero(&d, sizeof(d));
        memzero(&k, sizeof(k));
        memzero(&kinv_m, sizeof(kinv_m));
        return 0;
    }

err:
    memzero(&d, sizeof(d));
    memzero(&k, sizeof(k));
    memzero(&kinv_m, sizeof(kinv_m));
    return -1;
}

/** @copydoc ecdsa_p256_verify_digest */
int ecdsa_p256_verify_digest(const uint8_t public_key[64],
                             const uint8_t digest32[32],
                             const uint8_t signature[64])
{
    affine_point q;
    affine_point x;
    u256 qx;
    u256 qy;
    u256 r;
    u256 s;
    u256 z;
    u256 w_m;
    u256 u1_m;
    u256 u2_m;
    u256 u1;
    u256 u2;
    u256 r_m;
    u256 z_m;
    u256 sx;

    if (public_key == NULL || digest32 == NULL || signature == NULL) return -1;

    u256_from_be(&qx, public_key);
    u256_from_be(&qy, public_key + 32);
    if (u256_cmp(&qx, &P256_P) >= 0 || u256_cmp(&qy, &P256_P) >= 0) return -1;
    mont_from(&q.x, &qx, &P256_P, &P256_P_R2, 0x00000001U);
    mont_from(&q.y, &qy, &P256_P, &P256_P_R2, 0x00000001U);
    if (!point_is_on_curve(&q)) return -1;

    u256_from_be(&r, signature);
    u256_from_be(&s, signature + 32);
    if (u256_is_zero(&r) || u256_cmp(&r, &P256_N) >= 0 ||
        u256_is_zero(&s) || u256_cmp(&s, &P256_N) >= 0) {
        return -1;
    }

    u256_from_be(&z, digest32);
    if (u256_cmp(&z, &P256_N) >= 0) (void)u256_sub_raw(&z, &z, &P256_N);

    mont_from(&sx, &s, &P256_N, &P256_N_R2, 0xee00bc4fU);
    if (scalar_inv(&w_m, &sx) != 0) return -1;
    mont_from(&z_m, &z, &P256_N, &P256_N_R2, 0xee00bc4fU);
    mont_from(&r_m, &r, &P256_N, &P256_N_R2, 0xee00bc4fU);
    scalar_mul(&u1_m, &z_m, &w_m);
    scalar_mul(&u2_m, &r_m, &w_m);
    mont_to(&u1, &u1_m, &P256_N, 0xee00bc4fU);
    mont_to(&u2, &u2_m, &P256_N, 0xee00bc4fU);

    if (point_double_mul(&x, &u1, &q, &u2) != 0) return -1;
    mont_to(&sx, &x.x, &P256_P, 0x00000001U);
    if (u256_cmp(&sx, &P256_N) >= 0) (void)u256_sub_raw(&sx, &sx, &P256_N);
    return u256_cmp(&sx, &r) == 0 ? 0 : -1;
}
