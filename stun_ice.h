#ifndef STUN_ICE_H
#define STUN_ICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct stun_ice_config {
    const char *sender_ufrag;
    const char *target_ufrag;
    const char *target_password;
    uint32_t priority;
    uint64_t tie_breaker;
    bool controlling;
};

/* Returns zero if credentials are invalid or the packet would be too large. */
size_t stun_ice_packet_size(const struct stun_ice_config *config);

/* Build one authenticated ICE Binding Request. txid must contain 12 random bytes. */
bool stun_ice_build(const struct stun_ice_config *config,
                    const unsigned char txid[12],
                    unsigned char *packet, size_t capacity);

struct stun_ice_response {
    unsigned char txid[12];
    unsigned error_code;  /* zero for Binding Success */
    bool authenticated;   /* authentication failures may have no MI */
};

/* Rejects malformed packets and invalid FINGERPRINT or MESSAGE-INTEGRITY. */
bool stun_ice_parse_response(const unsigned char *packet, size_t length,
                             const char *target_password,
                             struct stun_ice_response *response);

#endif
