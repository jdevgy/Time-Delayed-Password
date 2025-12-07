// secure_hardened.c
// Hardened single-file AES-256-CBC with obfuscated key derivation,
// plus simple fixed-key AES-256-CBC helpers.
//
// Exports:
//   int aes256cbc_encrypt(const uint8_t* pt, int pt_len, uint8_t* out);
//   int aes256cbc_decrypt(const uint8_t* in, int in_len, uint8_t* out);
//   int simple_encrypt(const uint8_t *pt, int pt_len, uint8_t *out, int out_cap);
//   int simple_decrypt(const uint8_t *in, int in_len, uint8_t *out, int out_cap);
//
// Build (Linux):
//   gcc -O2 -fPIC -fvisibility=hidden -Wall -Wextra -Wl,-z,relro,-z,now -shared secure_hardened.c -lcrypto -o libsecure_aes.so
//   strip --strip-unneeded libsecure_aes.so

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <unistd.h>
#include <time.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

// ===================== Shared utility: secure_zero =====================
static void secure_zero(void *p, size_t n) { if (p && n) OPENSSL_cleanse(p, n); }

// ===================== Simple fixed-key AES-256-CBC APIs =====================
// WARNING: Embedding keys in a client binary is insecure and can be extracted.
static const uint8_t SIMPLE_AES256_KEY[32] = {
    0x42,0x67,0x91,0xAD,0x53,0xFE,0x1C,0x20,
    0x8A,0x3D,0x7B,0xE4,0x55,0xC9,0x13,0xF0,
    0x29,0x6E,0x84,0xDA,0x10,0x33,0x5F,0x77,
    0x88,0x9C,0xA1,0xB2,0xC3,0xD4,0xE5,0xF6
};

// Encrypts plaintext (pt, pt_len) with AES-256-CBC using SIMPLE_AES256_KEY.
// Generates a random 16-byte IV and outputs: [IV || CIPHERTEXT] into out.
// out_cap must be at least 16 + pt_len + 16 (for padding worst-case).
// Returns total bytes written (>= 32) on success, negative on error.
__attribute__((visibility("default")))
int simple_encrypt(const uint8_t *pt, int pt_len, uint8_t *out, int out_cap) {
    if (!pt || pt_len < 0 || !out || out_cap <= 16) return -1;

    uint8_t iv[16];
    if (RAND_bytes(iv, sizeof iv) != 1) return -2;

    if (out_cap < 16 + pt_len + 16) return -3; // ensure enough space

    // Write IV prefix
    memcpy(out, iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { secure_zero(iv, sizeof iv); return -4; }

    int rc = -100;
    int len = 0, total = 16;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SIMPLE_AES256_KEY, iv) != 1) { rc = -5; break; }

        int clen = 0;
        if (EVP_EncryptUpdate(ctx, out + total, &clen, pt, pt_len) != 1) { rc = -6; break; }
        total += clen;

        int flen = 0;
        if (EVP_EncryptFinal_ex(ctx, out + total, &flen) != 1) { rc = -7; break; }
        total += flen;

        rc = total; // success: bytes written = 16 (IV) + ciphertext_len
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    secure_zero(iv, sizeof iv);
    return rc;
}

// Decrypts input formatted as [IV || CIPHERTEXT] using SIMPLE_AES256_KEY.
// Writes plaintext to out. out_cap must be at least (in_len - 16).
// Returns plaintext length on success (>= 0), negative on error.
__attribute__((visibility("default")))
int simple_decrypt(const uint8_t *in, int in_len, uint8_t *out, int out_cap) {
    if (!in || in_len < 16 || !out) return -1;

    const uint8_t *iv = in;
    const uint8_t *ct = in + 16;
    int ct_len = in_len - 16;

    if (ct_len <= 0) return -2;
    if (out_cap < ct_len) return -3; // upper bound before removing padding

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -4;

    int rc = -100;
    int len = 0, total = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SIMPLE_AES256_KEY, iv) != 1) { rc = -5; break; }

        int plen = 0;
        if (EVP_DecryptUpdate(ctx, out + total, &plen, ct, ct_len) != 1) { rc = -6; break; }
        total += plen;

        int flen = 0;
        if (EVP_DecryptFinal_ex(ctx, out + total, &flen) != 1) { rc = -7; break; }
        total += flen;

        rc = total; // plaintext length
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

// ===================== Hardened derived-key AES-256-CBC APIs =====================

// HMAC key trailer for helper
static const uint8_t HMAC_KEY_PART2[] = {
    0xB1,0x9E,0xA3,0x47,0x5C,0xD2,0x0A,0xF4,
    0x39,0x88,0x1D,0x6E,0x72,0xC5,0x9B,0x0F
};

// ============================== Config/Constants ==============================
// Replace these shard contents per build using your generator one-liner.
// NOTE: If you change these and recompile, old ciphertexts won't decrypt with the new build.

static const uint8_t SHARD_A[24] = {
    0x72,0xE1,0x1C,0x55,0x0A,0xC4,0x9D,0x2B,0x33,0x80,0x19,0x6E,
    0xAB,0x04,0xF1,0x57,0x5E,0x21,0xC8,0x3D,0x90,0xEE,0x74,0x49
};
static const uint8_t SHARD_B[24] = {
    0xA9,0x13,0x5D,0x60,0x02,0xB7,0x48,0x1C,0xD2,0x7F,0xE0,0x38,
    0x4B,0x99,0x16,0x8A,0x27,0x51,0xCB,0xF5,0x30,0x0D,0x66,0x82
};
static const uint8_t SHARD_C[24] = {
    0x58,0x0F,0xE6,0x42,0xBA,0x9A,0x07,0x6C,0x21,0xCF,0x13,0x74,
    0x93,0xDE,0x2A,0x40,0x8E,0xB2,0x65,0x01,0xFD,0x57,0x19,0xAA
};
static const uint8_t SHARD_D[24] = {
    0x3C,0xBE,0x84,0x28,0x71,0xD5,0x0E,0x92,0x46,0xAD,0xF8,0x10,
    0x6F,0x23,0xC1,0x5B,0xE3,0x35,0x7A,0x04,0xB6,0xD9,0x2E,0x58
};

// Per-build seed; replace per build.
static const uint32_t BUILD_SEED = 0xC3D2B17Fu;

// ============================== Utility (hardened) ==============================
#define likely(x)   __builtin_expect(!!(x),1)
#define unlikely(x) __builtin_expect(!!(x),0)

static uint32_t xorshift32(uint32_t *s) {
    uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; *s = x; return x;
}

static int get_rng(uint8_t *buf, size_t n) {
#if defined(__linux__)
    ssize_t r = getrandom(buf, n, 0);
    if (r == (ssize_t)n) return 1;
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t got = fread(buf,1,n,f);
    fclose(f);
    return got == n;
}

static void harden_process(void) {
#if defined(__linux__)
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit rl = {0,0};
    setrlimit(RLIMIT_CORE, &rl);
#endif
}

static int suspicious_env(void) {
    const char* e;
    e = getenv("LD_PRELOAD"); if (e && *e) return 1;
    e = getenv("LD_DEBUG"); if (e && *e) return 1;
    e = getenv("FRIDA_VERSION"); if (e && *e) return 1;
    e = getenv("DYLD_INSERT_LIBRARIES"); if (e && *e) return 1;
    return 0;
}

// ============================== Deterministic per-build salt ==============================
static uint8_t g_salt[32];
static int g_salt_ready = 0;

static void init_process_salt(void) {
    if (g_salt_ready) return;

    // Derive salt deterministically from shards and BUILD_SEED.
    uint8_t buf[24*4 + 4];
    unsigned int outlen = 0;

    memcpy(buf,       SHARD_A, 24);
    memcpy(buf + 24,  SHARD_B, 24);
    memcpy(buf + 48,  SHARD_C, 24);
    memcpy(buf + 72,  SHARD_D, 24);
    memcpy(buf + 96, &BUILD_SEED, 4);

    // Domain-separate with a label
    const unsigned char label[] = "SALTv1";
    HMAC(EVP_sha256(), buf, sizeof buf, label, (int)sizeof(label)-1, g_salt, &outlen);

    OPENSSL_cleanse(buf, sizeof buf);
    g_salt_ready = 1;
}

// ============================== S-Box Reconstruction ==============================
static void build_sbox(uint8_t sbox[256], uint8_t inv[256]) {
    for (int i=0;i<256;i++) sbox[i]=(uint8_t)i;
    uint32_t seed = BUILD_SEED;
    for (size_t i=0;i<24;i++) { seed ^= (uint32_t)SHARD_A[i] << ((i%4)*8); seed += 0x9E3779B9u; seed = (seed<<7) | (seed>>25); }
    for (size_t i=0;i<24;i++) { seed ^= (uint32_t)SHARD_B[i] << ((i%4)*8); seed += 0x85EBCA6Bu; seed = (seed<<9) | (seed>>23); }
    for (size_t i=0;i<24;i++) { seed ^= (uint32_t)SHARD_C[i] << ((i%4)*8); seed += 0xC2B2AE35u; seed = (seed<<11)| (seed>>21); }
    for (size_t i=0;i<24;i++) { seed ^= (uint32_t)SHARD_D[i] << ((i%4)*8); seed += 0x27D4EB2Fu; seed = (seed<<13)| (seed>>19); }

    for (int i=255;i>0;i--) {
        uint32_t r = xorshift32(&seed);
        int j = (int)(r % (uint32_t)(i+1));
        uint8_t t = sbox[i]; sbox[i] = sbox[j]; sbox[j] = t;
    }
    for (int i=0;i<256;i++) inv[sbox[i]] = (uint8_t)i;
}

// ============================== Mask Construction (Stage A) ==============================
static void build_mask(uint8_t M[32]) {
    uint8_t sbox[256], inv[256];
    build_sbox(sbox, inv);

    uint32_t st = BUILD_SEED ^ 0xA5A5A5A5u;
    for (int i=0;i<32;i++) {
        st ^= (st << 7) + (st >> 9) + (0x9E + (i*13));
        uint8_t v = (uint8_t)(st ^ (st>>8) ^ (st>>16) ^ (st>>24));
        M[i] = sbox[v];
    }

    uint32_t acc = 0;
    for (int pass=0; pass<6; pass++) {
        uint32_t x = (uint32_t)(pass*pass + 1);
        if (((x*x + 3) % 4) == (((x%4)*(x%4) + 3) % 4)) {
            for (int i=0;i<32;i++) {
                uint8_t b = 0;
                const uint8_t *S; size_t off;
                switch ((i + pass) % 4) {
                    case 0: S = SHARD_A; off = (size_t)((i*3 + pass*5) % 24); b = S[off] ^ (uint8_t)(i*11 + pass*7); break;
                    case 1: S = SHARD_B; off = (size_t)((i*5 + pass*3) % 24); b = (uint8_t)((S[off] + i + pass) ^ 0x5A); break;
                    case 2: S = SHARD_C; off = (size_t)((i*7 + pass*2) % 24); b = (uint8_t)((S[off] ^ 0xA6) + (i*3)); break;
                    default:S = SHARD_D; off = (size_t)((i*9 + pass) % 24);   b = (uint8_t)((S[off] - (i+pass)) ^ 0xC3); break;
                }
                uint8_t t = (uint8_t)(M[(i+pass*3)&31] ^ sbox[(uint8_t)(b + acc)]);
                t = (uint8_t)(t + (t<<3)) ^ (uint8_t)(t>>5);
                M[i] = inv[(uint8_t)(M[i] ^ t)];
                acc += (uint32_t)(b + i + pass + 1);
            }
        } else {
            for (int i=31;i>=0;i--) {
                M[i] ^= (uint8_t)(i*pass*17);
                M[i] = sbox[M[i]];
            }
        }
        uint8_t tmp = M[0];
        for (int k=0;k<31;k++) M[k] = M[k+1] ^ (uint8_t)(k + pass*13);
        M[31] = tmp ^ (uint8_t)(0xA5 + pass);
    }

    for (int i=0;i<32;i++) {
        M[i] ^= (uint8_t)(acc >> (i & 7));
        M[i] = sbox[M[i]] ^ (uint8_t)(i*29 + 113);
    }

    secure_zero(inv, sizeof inv);
    secure_zero(sbox, sizeof sbox);
}

// ============================== Key Derivation (Stage B) ==============================
static void derive_key(uint8_t K[32]) {
    uint8_t M[32];
    build_mask(M);

    init_process_salt(); // deterministic, cached once per process

    unsigned int outlen = 0;
    HMAC(EVP_sha256(), g_salt, 32, M, sizeof M, K, &outlen);

    secure_zero(M, sizeof M);
}

// ============================== Streaming Key Provider ==============================
typedef struct {
    uint8_t K[32];
    int have; // 0 none, 16 first half, 32 full
} key_stream_t;

static void ks_init(key_stream_t *ks) { memset(ks, 0, sizeof *ks); }
static int ks_fill(key_stream_t *ks) {
    if (ks->have == 0) {
        derive_key(ks->K);
        ks->have = 16;
        return 16;
    } else if (ks->have == 16) {
        uint8_t K2[32];
        derive_key(K2);
        for (int i=0;i<16;i++) ks->K[16+i] = (uint8_t)(K2[i] ^ K2[16+i] ^ ks->K[i] ^ (uint8_t)(i*53));
        secure_zero(K2, sizeof K2);
        ks->have = 32;
        return 16;
    }
    return 0;
}
static void ks_get_block(key_stream_t *ks, int idx_block, uint8_t out16[16]) {
    if (idx_block == 0) { if (ks->have < 16) ks_fill(ks); memcpy(out16, ks->K, 16); }
    else { if (ks->have < 32) ks_fill(ks); memcpy(out16, ks->K+16, 16); }
}

// ============================== Crypto (hardened) ==============================
static int rand_bytes(uint8_t *buf, size_t n) {
    // use stronger sys RNG; if that fails, fallback to RAND_bytes
    if (get_rng(buf, n)) return 1;
    return RAND_bytes(buf, (int)n) == 1;
}

__attribute__((visibility("default")))
int aes256cbc_encrypt(const uint8_t *pt, int pt_len, uint8_t *out) {
    if (!pt || !out || pt_len < 0) return -1;
    if (suspicious_env()) return -2;
    harden_process();
    init_process_salt();

    uint8_t iv[16];
    if (!rand_bytes(iv, sizeof iv)) return -1;
    memcpy(out, iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { secure_zero(iv, sizeof iv); return -1; }

    key_stream_t ks; ks_init(&ks);
    uint8_t kblk0[16], kblk1[16];
    ks_get_block(&ks, 0, kblk0);
    ks_get_block(&ks, 1, kblk1);
    uint8_t key[32];
    memcpy(key, kblk0, 16); memcpy(key+16, kblk1, 16);
    secure_zero(kblk0, sizeof kblk0);
    secure_zero(kblk1, sizeof kblk1);

    int ok = 1, len = 0, ct = 0;
    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 1;
    secure_zero(key, sizeof key);
    if (!ok) { EVP_CIPHER_CTX_free(ctx); secure_zero(iv, sizeof iv); secure_zero(&ks, sizeof ks); return -1; }

    ok &= EVP_EncryptUpdate(ctx, out+16, &len, pt, pt_len) == 1; ct = len;
    int ok_final = EVP_EncryptFinal_ex(ctx, out+16+ct, &len);
    if (ok && ok_final == 1) ct += len; else ct = -3;

    EVP_CIPHER_CTX_free(ctx);
    secure_zero(iv, sizeof iv);
    secure_zero(&ks, sizeof ks);

    return (ct < 0) ? ct : (16 + ct);
}

__attribute__((visibility("default")))
int aes256cbc_decrypt(const uint8_t *in, int in_len, uint8_t *out) {
    if (!in || !out || in_len < 16) return -1;
    if (suspicious_env()) return -2;
    harden_process();
    init_process_salt();

    uint8_t iv[16];
    memcpy(iv, in, 16);
    const uint8_t *c = in + 16; int clen = in_len - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { secure_zero(iv,sizeof iv); return -1; }

    key_stream_t ks; ks_init(&ks);
    uint8_t kblk0[16], kblk1[16];
    ks_get_block(&ks, 0, kblk0);
    ks_get_block(&ks, 1, kblk1);
    uint8_t key[32];
    memcpy(key, kblk0, 16); memcpy(key+16, kblk1, 16);
    secure_zero(kblk0, sizeof kblk0);
    secure_zero(kblk1, sizeof kblk1);

    int ok = 1, len = 0, pt = 0;
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 1;
    secure_zero(key, sizeof key);
    if (!ok) { EVP_CIPHER_CTX_free(ctx); secure_zero(iv,sizeof iv); secure_zero(&ks, sizeof ks); return -1; }

    ok &= EVP_DecryptUpdate(ctx, out, &len, c, clen) == 1; pt = len;
    int ok_final = EVP_DecryptFinal_ex(ctx, out+pt, &len);
    if (ok && ok_final == 1) pt += len; else pt = -3;

    EVP_CIPHER_CTX_free(ctx);
    secure_zero(iv, sizeof iv);
    secure_zero(&ks, sizeof ks);

    return pt;
}

// ============================== Helper: HMAC SHA-256 with key part ==============================
static void bytes_to_hex(const uint8_t *in, size_t n, char *out_hex) {
    static const char *hexd = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out_hex[2*i]   = hexd[(in[i] >> 4) & 0xF];
        out_hex[2*i+1] = hexd[in[i] & 0xF];
    }
    out_hex[2*n] = '\0';
}

__attribute__((visibility("default")))
int hmac_sha256_text_with_keypart(const char *message,
                                  const char *key_part,
                                  char *out_hex /* size >= 65 */) {
    if (!message || !key_part || !out_hex) return -1;

    const uint8_t *msg = (const uint8_t *)message;
    size_t msg_len = strlen(message);

    const uint8_t *kp1 = (const uint8_t *)key_part;
    size_t kp1_len = strlen(key_part);

    enum { MAX_K = 4096 };
    if (kp1_len + sizeof(HMAC_KEY_PART2) > MAX_K) return -2;

    uint8_t key_buf[MAX_K];
    memcpy(key_buf, kp1, kp1_len);
    memcpy(key_buf + kp1_len, HMAC_KEY_PART2, sizeof(HMAC_KEY_PART2));
    size_t key_len = kp1_len + sizeof(HMAC_KEY_PART2);

    unsigned int dlen = 0;
    uint8_t digest[32];
    unsigned char *res = HMAC(EVP_sha256(),
                              key_buf, (int)key_len,
                              msg, (int)msg_len,
                              digest, &dlen);

    OPENSSL_cleanse(key_buf, key_len);

    if (!res || dlen != 32) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return -3;
    }

    bytes_to_hex(digest, 32, out_hex);
    OPENSSL_cleanse(digest, sizeof(digest));
    return 64;
}
