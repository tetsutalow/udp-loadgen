#include "stun_ice.h"

#include <string.h>

#define STUN_HEADER_SIZE 20U
#define STUN_COOKIE UINT32_C(0x2112a442)
#define STUN_FINGERPRINT_XOR UINT32_C(0x5354554e)

struct sha1_ctx {
    uint32_t state[5];
    uint64_t bytes;
    unsigned char block[64];
    size_t used;
};

static void put_be16(unsigned char *out, uint16_t value)
{
    out[0] = (unsigned char)(value >> 8);
    out[1] = (unsigned char)value;
}

static void put_be32(unsigned char *out, uint32_t value)
{
    for (int i = 3; i >= 0; --i) {
        out[i] = (unsigned char)value;
        value >>= 8;
    }
}

static void put_be64(unsigned char *out, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[i] = (unsigned char)value;
        value >>= 8;
    }
}

static uint32_t get_be32(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint16_t get_be16(const unsigned char *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t rol32(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32U - count));
}

static void sha1_compress(struct sha1_ctx *ctx, const unsigned char block[64])
{
    uint32_t words[80];
    for (size_t i = 0; i < 16; ++i) {
        words[i] = get_be32(block + i * 4);
    }
    for (size_t i = 16; i < 80; ++i) {
        words[i] = rol32(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    }
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    for (size_t i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = UINT32_C(0x5a827999);
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = UINT32_C(0x6ed9eba1);
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = UINT32_C(0x8f1bbcdc);
        } else {
            f = b ^ c ^ d;
            k = UINT32_C(0xca62c1d6);
        }
        uint32_t next = rol32(a, 5) + f + e + k + words[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = next;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(struct sha1_ctx *ctx)
{
    *ctx = (struct sha1_ctx){
        .state = {
            UINT32_C(0x67452301), UINT32_C(0xefcdab89), UINT32_C(0x98badcfe),
            UINT32_C(0x10325476), UINT32_C(0xc3d2e1f0),
        },
    };
}

static void sha1_update(struct sha1_ctx *ctx, const unsigned char *data, size_t length)
{
    ctx->bytes += length;
    while (length != 0) {
        size_t part = sizeof(ctx->block) - ctx->used;
        if (part > length) {
            part = length;
        }
        memcpy(ctx->block + ctx->used, data, part);
        ctx->used += part;
        data += part;
        length -= part;
        if (ctx->used == sizeof(ctx->block)) {
            sha1_compress(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha1_finish(struct sha1_ctx *ctx, unsigned char digest[20])
{
    uint64_t bits = ctx->bytes * 8;
    unsigned char padding[64] = {0x80};
    size_t padding_length = ctx->used < 56 ? 56 - ctx->used : 120 - ctx->used;
    sha1_update(ctx, padding, padding_length);
    unsigned char length_bytes[8];
    put_be64(length_bytes, bits);
    sha1_update(ctx, length_bytes, sizeof(length_bytes));
    for (size_t i = 0; i < 5; ++i) {
        put_be32(digest + i * 4, ctx->state[i]);
    }
}

static void hmac_sha1(const unsigned char *key, size_t key_length,
                      const unsigned char *first, size_t first_length,
                      const unsigned char *second, size_t second_length,
                      unsigned char digest[20])
{
    unsigned char key_block[64] = {0};
    if (key_length > sizeof(key_block)) {
        struct sha1_ctx key_hash;
        sha1_init(&key_hash);
        sha1_update(&key_hash, key, key_length);
        sha1_finish(&key_hash, key_block);
    } else {
        memcpy(key_block, key, key_length);
    }

    unsigned char inner_key[64];
    unsigned char outer_key[64];
    for (size_t i = 0; i < sizeof(key_block); ++i) {
        inner_key[i] = key_block[i] ^ 0x36U;
        outer_key[i] = key_block[i] ^ 0x5cU;
    }

    unsigned char inner_digest[20];
    struct sha1_ctx hash;
    sha1_init(&hash);
    sha1_update(&hash, inner_key, sizeof(inner_key));
    sha1_update(&hash, first, first_length);
    if (second_length != 0) {
        sha1_update(&hash, second, second_length);
    }
    sha1_finish(&hash, inner_digest);
    sha1_init(&hash);
    sha1_update(&hash, outer_key, sizeof(outer_key));
    sha1_update(&hash, inner_digest, sizeof(inner_digest));
    sha1_finish(&hash, digest);
}

static uint32_t crc32(const unsigned char *data, size_t length)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ ((crc & 1U) ? UINT32_C(0xedb88320) : 0U);
        }
    }
    return crc ^ UINT32_MAX;
}

static size_t padded_size(size_t length)
{
    return (length + 3U) & ~(size_t)3U;
}

static bool valid_ufrag(const char *value)
{
    if (value == NULL) {
        return false;
    }
    size_t length = strlen(value);
    if (length < 4 || length > 256) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/')) {
            return false;
        }
    }
    return true;
}

size_t stun_ice_packet_size(const struct stun_ice_config *config)
{
    if (config == NULL || !valid_ufrag(config->sender_ufrag) ||
        !valid_ufrag(config->target_ufrag) || config->target_password == NULL ||
        config->target_password[0] == '\0' || strlen(config->target_password) > 256 ||
        config->priority == 0) {
        return 0;
    }
    size_t username_length = strlen(config->target_ufrag) + 1 +
                             strlen(config->sender_ufrag);
    return STUN_HEADER_SIZE + 4 + padded_size(username_length) +
           8 + 12 + 24 + 8;
}

bool stun_ice_build(const struct stun_ice_config *config,
                    const unsigned char txid[12],
                    unsigned char *packet, size_t capacity)
{
    size_t length = stun_ice_packet_size(config);
    if (length == 0 || capacity < length || txid == NULL || packet == NULL) {
        return false;
    }
    memset(packet, 0, length);
    put_be16(packet, 0x0001);  /* Binding Request */
    put_be32(packet + 4, STUN_COOKIE);
    memcpy(packet + 8, txid, 12);

    size_t target_length = strlen(config->target_ufrag);
    size_t sender_length = strlen(config->sender_ufrag);
    size_t username_length = target_length + 1 + sender_length;
    size_t pos = STUN_HEADER_SIZE;
    put_be16(packet + pos, 0x0006);  /* USERNAME */
    put_be16(packet + pos + 2, (uint16_t)username_length);
    memcpy(packet + pos + 4, config->target_ufrag, target_length);
    packet[pos + 4 + target_length] = ':';
    memcpy(packet + pos + 5 + target_length, config->sender_ufrag, sender_length);
    pos += 4 + padded_size(username_length);

    put_be16(packet + pos, 0x0024);  /* PRIORITY */
    put_be16(packet + pos + 2, 4);
    put_be32(packet + pos + 4, config->priority);
    pos += 8;

    put_be16(packet + pos, config->controlling ? 0x802a : 0x8029);
    put_be16(packet + pos + 2, 8);
    put_be64(packet + pos + 4, config->tie_breaker);
    pos += 12;

    size_t integrity_offset = pos;
    put_be16(packet + pos, 0x0008);  /* MESSAGE-INTEGRITY */
    put_be16(packet + pos + 2, 20);
    pos += 24;
    /* RFC 8489 section 14.5: header length ends at MI; HMAC input ends before MI. */
    put_be16(packet + 2, (uint16_t)(pos - STUN_HEADER_SIZE));
    hmac_sha1((const unsigned char *)config->target_password,
              strlen(config->target_password), packet, integrity_offset, NULL, 0,
              packet + integrity_offset + 4);

    put_be16(packet + 2, (uint16_t)(length - STUN_HEADER_SIZE));
    put_be16(packet + pos, 0x8028);  /* FINGERPRINT, always last */
    put_be16(packet + pos + 2, 4);
    put_be32(packet + pos + 4, crc32(packet, pos) ^ STUN_FINGERPRINT_XOR);
    return true;
}

bool stun_ice_parse_response(const unsigned char *packet, size_t length,
                             const char *target_password,
                             struct stun_ice_response *response)
{
    if (packet == NULL || response == NULL || target_password == NULL ||
        length < STUN_HEADER_SIZE || length > 65507 ||
        get_be16(packet + 2) != length - STUN_HEADER_SIZE ||
        get_be32(packet + 4) != STUN_COOKIE) {
        return false;
    }
    uint16_t message_type = get_be16(packet);
    if (message_type != 0x0101 && message_type != 0x0111) {
        return false;
    }

    size_t integrity_offset = 0;
    size_t fingerprint_offset = 0;
    unsigned error_code = 0;
    for (size_t pos = STUN_HEADER_SIZE; pos < length;) {
        if (length - pos < 4) {
            return false;
        }
        uint16_t kind = get_be16(packet + pos);
        uint16_t value_length = get_be16(packet + pos + 2);
        size_t attribute_size = 4 + padded_size(value_length);
        if (attribute_size > length - pos) {
            return false;
        }
        if (kind == 0x0008) {
            if (value_length != 20 || integrity_offset != 0 || fingerprint_offset != 0) {
                return false;
            }
            integrity_offset = pos;
        } else if (kind == 0x8028) {
            if (value_length != 4 || pos + attribute_size != length ||
                fingerprint_offset != 0) {
                return false;
            }
            fingerprint_offset = pos;
        } else if (kind == 0x0009) {
            if (value_length < 4) {
                return false;
            }
            const unsigned char *value = packet + pos + 4;
            error_code = (unsigned)(value[2] & 0x07U) * 100U + value[3];
        }
        pos += attribute_size;
    }
    if (fingerprint_offset == 0 ||
        get_be32(packet + fingerprint_offset + 4) !=
            (crc32(packet, fingerprint_offset) ^ STUN_FINGERPRINT_XOR)) {
        return false;
    }
    if (message_type == 0x0101 && integrity_offset == 0) {
        return false;
    }
    if (message_type == 0x0111 && error_code == 0) {
        return false;
    }
    if (integrity_offset != 0) {
        unsigned char adjusted_header[STUN_HEADER_SIZE];
        memcpy(adjusted_header, packet, sizeof(adjusted_header));
        put_be16(adjusted_header + 2,
                 (uint16_t)(integrity_offset + 24 - STUN_HEADER_SIZE));
        unsigned char digest[20];
        hmac_sha1((const unsigned char *)target_password, strlen(target_password),
                  adjusted_header, sizeof(adjusted_header),
                  packet + STUN_HEADER_SIZE, integrity_offset - STUN_HEADER_SIZE,
                  digest);
        unsigned difference = 0;
        for (size_t i = 0; i < sizeof(digest); ++i) {
            difference |= digest[i] ^ packet[integrity_offset + 4 + i];
        }
        if (difference != 0) {
            return false;
        }
    }
    memcpy(response->txid, packet + 8, sizeof(response->txid));
    response->error_code = error_code;
    response->authenticated = integrity_offset != 0;
    return true;
}
