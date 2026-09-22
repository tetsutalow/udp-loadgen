#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "stun_ice.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_UDP_PAYLOAD 65507U
#define STAMP_SIZE 16U
#define RESPONSE_WINDOW 65536U
#define RESPONSE_BUCKETS 131072U

static volatile sig_atomic_t stop_requested;

struct options {
    const char *src_ip;
    const char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    size_t payload_size;
    double pps;
    double duration;
    uint64_t count;
    int fill;
    int sndbuf;
    const char *interface;
    const char *sender_ufrag;
    const char *target_ufrag;
    const char *target_password;
    const char *target_password_env;
    uint32_t priority;
    bool ice_binding;
    bool controlling;
    bool no_response_stats;
    double response_wait;
    bool spoof_source;
    bool stamp;
    bool quiet;
};

static void on_signal(int signo)
{
    (void)signo;
    stop_requested = 1;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void sleep_until(uint64_t target_ns)
{
    struct timespec deadline = {
        .tv_sec = (time_t)(target_ns / UINT64_C(1000000000)),
        .tv_nsec = (long)(target_ns % UINT64_C(1000000000)),
    };

    while (!stop_requested) {
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        if (rc == 0) {
            return;
        }
        if (rc != EINTR) {
            errno = rc;
            perror("clock_nanosleep");
            stop_requested = 1;
            return;
        }
    }
}

static void put_be64(unsigned char *dst, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        dst[i] = (unsigned char)(value & 0xffU);
        value >>= 8;
    }
}

static void put_stamp(unsigned char *payload, uint64_t sequence, uint64_t timestamp_ns)
{
    memcpy(payload, "ULG1", 4);
    uint32_t seq32 = htonl((uint32_t)sequence);
    memcpy(payload + 4, &seq32, sizeof(seq32));
    put_be64(payload + 8, timestamp_ns);
}

static bool random_bytes(unsigned char *out, size_t length)
{
    while (length != 0) {
        ssize_t received = getrandom(out, length, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return false;
        }
        out += (size_t)received;
        length -= (size_t)received;
    }
    return true;
}

struct pending_request {
    unsigned char txid[12];
    uint64_t sent_ns;
    int next;
    int previous;
    uint32_t bucket;
    bool active;
};

struct response_tracker {
    struct pending_request *pending;
    int *heads;
    size_t cursor;
    size_t active;
    uint64_t evicted;
    uint64_t success;
    uint64_t error;
    uint64_t error_401;
    uint64_t error_487;
    uint64_t unauthenticated_error;
    uint64_t invalid;
    uint64_t unmatched;
    uint64_t receive_errors;
    uint64_t rtt_min_ns;
    uint64_t rtt_max_ns;
    long double rtt_sum_ns;
};

static uint32_t txid_bucket(const unsigned char txid[12])
{
    uint32_t hash = UINT32_C(2166136261);
    for (size_t i = 0; i < 12; ++i) {
        hash = (hash ^ txid[i]) * UINT32_C(16777619);
    }
    return hash & (RESPONSE_BUCKETS - 1U);
}

static bool tracker_init(struct response_tracker *tracker)
{
    memset(tracker, 0, sizeof(*tracker));
    tracker->pending = calloc(RESPONSE_WINDOW, sizeof(*tracker->pending));
    tracker->heads = malloc(RESPONSE_BUCKETS * sizeof(*tracker->heads));
    if (tracker->pending == NULL || tracker->heads == NULL) {
        free(tracker->pending);
        free(tracker->heads);
        memset(tracker, 0, sizeof(*tracker));
        return false;
    }
    for (size_t i = 0; i < RESPONSE_BUCKETS; ++i) {
        tracker->heads[i] = -1;
    }
    return true;
}

static void tracker_remove(struct response_tracker *tracker, int index)
{
    struct pending_request *entry = &tracker->pending[index];
    if (entry->previous >= 0) {
        tracker->pending[entry->previous].next = entry->next;
    } else {
        tracker->heads[entry->bucket] = entry->next;
    }
    if (entry->next >= 0) {
        tracker->pending[entry->next].previous = entry->previous;
    }
    entry->active = false;
    --tracker->active;
}

static void tracker_insert(struct response_tracker *tracker,
                           const unsigned char txid[12], uint64_t sent_ns)
{
    int index = (int)tracker->cursor;
    tracker->cursor = (tracker->cursor + 1U) % RESPONSE_WINDOW;
    struct pending_request *entry = &tracker->pending[index];
    if (entry->active) {
        tracker_remove(tracker, index);
        ++tracker->evicted;
    }
    memcpy(entry->txid, txid, sizeof(entry->txid));
    entry->sent_ns = sent_ns;
    entry->bucket = txid_bucket(txid);
    entry->previous = -1;
    entry->next = tracker->heads[entry->bucket];
    if (entry->next >= 0) {
        tracker->pending[entry->next].previous = index;
    }
    tracker->heads[entry->bucket] = index;
    entry->active = true;
    ++tracker->active;
}

static int tracker_find(const struct response_tracker *tracker,
                        const unsigned char txid[12])
{
    for (int index = tracker->heads[txid_bucket(txid)]; index >= 0;
         index = tracker->pending[index].next) {
        if (memcmp(tracker->pending[index].txid, txid, 12) == 0) {
            return index;
        }
    }
    return -1;
}

static void drain_responses(int fd, struct response_tracker *tracker,
                            const char *target_password, unsigned limit)
{
    for (unsigned i = 0; i < limit; ++i) {
        unsigned char packet[MAX_UDP_PAYLOAD];
        ssize_t received = recv(fd, packet, sizeof(packet), MSG_DONTWAIT);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ++tracker->receive_errors;
            }
            return;
        }
        struct stun_ice_response response;
        if (!stun_ice_parse_response(packet, (size_t)received,
                                     target_password, &response)) {
            ++tracker->invalid;
            continue;
        }
        int index = tracker_find(tracker, response.txid);
        if (index < 0) {
            ++tracker->unmatched;
            continue;
        }
        uint64_t now_ns = monotonic_ns();
        uint64_t rtt_ns = now_ns - tracker->pending[index].sent_ns;
        tracker_remove(tracker, index);
        if (tracker->rtt_min_ns == 0 || rtt_ns < tracker->rtt_min_ns) {
            tracker->rtt_min_ns = rtt_ns;
        }
        if (rtt_ns > tracker->rtt_max_ns) {
            tracker->rtt_max_ns = rtt_ns;
        }
        tracker->rtt_sum_ns += rtt_ns;
        if (response.error_code == 0) {
            ++tracker->success;
        } else {
            ++tracker->error;
            if (response.error_code == 401) {
                ++tracker->error_401;
            }
            if (response.error_code == 487) {
                ++tracker->error_487;
            }
            if (!response.authenticated) {
                ++tracker->unauthenticated_error;
            }
        }
    }
}

static void wait_until_with_responses(int fd, struct response_tracker *tracker,
                                      const char *target_password, uint64_t deadline_ns)
{
    while (!stop_requested) {
        uint64_t now_ns = monotonic_ns();
        if (now_ns >= deadline_ns) {
            break;
        }
        uint64_t left_ns = deadline_ns - now_ns;
        uint64_t timeout_ms64 = left_ns / UINT64_C(1000000) +
                                (left_ns % UINT64_C(1000000) != 0);
        int timeout_ms = (int)(timeout_ms64 > INT32_MAX ? INT32_MAX : timeout_ms64);
        struct pollfd watched = {.fd = fd, .events = POLLIN};
        int result = poll(&watched, 1, timeout_ms);
        if (result > 0) {
            drain_responses(fd, tracker, target_password, 256);
        } else if (result < 0 && errno != EINTR) {
            ++tracker->receive_errors;
            break;
        }
    }
}

static bool is_lab_destination(struct in_addr address)
{
    uint32_t ip = ntohl(address.s_addr);

    return (ip & UINT32_C(0xff000000)) == UINT32_C(0x0a000000) ||       /* 10/8 */
           (ip & UINT32_C(0xfff00000)) == UINT32_C(0xac100000) ||       /* 172.16/12 */
           (ip & UINT32_C(0xffff0000)) == UINT32_C(0xc0a80000) ||       /* 192.168/16 */
           (ip & UINT32_C(0xff000000)) == UINT32_C(0x7f000000) ||       /* loopback */
           (ip & UINT32_C(0xffff0000)) == UINT32_C(0xa9fe0000) ||       /* link-local */
           (ip & UINT32_C(0xffc00000)) == UINT32_C(0x64400000) ||       /* CGNAT */
           (ip & UINT32_C(0xfffe0000)) == UINT32_C(0xc6120000) ||       /* benchmark */
           (ip & UINT32_C(0xffffff00)) == UINT32_C(0xc0000200) ||       /* TEST-NET-1 */
           (ip & UINT32_C(0xffffff00)) == UINT32_C(0xc6336400) ||       /* TEST-NET-2 */
           (ip & UINT32_C(0xffffff00)) == UINT32_C(0xcb007100);         /* TEST-NET-3 */
}

static bool is_unicast_source(struct in_addr address)
{
    uint32_t ip = ntohl(address.s_addr);
    return ip != 0 && ip != UINT32_MAX && (ip & UINT32_C(0xf0000000)) != UINT32_C(0xe0000000);
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s --src-ip ADDR --src-port PORT --dst-ip ADDR\n"
            "          --dst-port PORT [--size BYTES | --mode ice-binding ...] [options]\n\n"
            "Required:\n"
            "  --src-ip ADDR       Source IPv4 address\n"
            "  --src-port PORT     Source UDP port (0 chooses ephemeral in normal mode)\n"
            "  --dst-ip ADDR       Destination IPv4 address\n"
            "  --dst-port PORT     Destination UDP port (1-65535)\n"
            "  --size BYTES        UDP mode payload size (0-%u)\n"
            "  --mode MODE         udp (default) or ice-binding\n\n"
            "Load controls:\n"
            "  --pps RATE          Packets per second; 0 means unlimited (default: 1000)\n"
            "  --duration SEC      Stop after seconds; 0 disables (default: 10)\n"
            "  --count PACKETS     Stop after attempts; 0 disables (default: 0)\n"
            "                       When both are set, the first limit wins\n"
            "  --sndbuf BYTES      Request a socket send-buffer size\n\n"
            "ICE Binding Request mode (no --size, --fill, or --stamp):\n"
            "  --sender-ufrag TEXT  Sender's ICE username fragment\n"
            "  --target-ufrag TEXT  Target's ICE username fragment\n"
            "  --target-password TEXT      Target's ICE password (visible in process list)\n"
            "  --target-password-env NAME  Read target password from environment variable\n"
            "  --role ROLE          controlling or controlled (sender's role)\n"
            "  --priority VALUE     Peer-reflexive priority (default: 0x6e0001ff)\n"
            "                       ICE mode defaults to 1 pps if --pps is omitted\n\n"
            "  --response-wait SEC  Collect replies after sending (default: 1; max: 60)\n"
            "  --no-response-stats  Disable reply parsing during ICE sending\n"
            "                       Spoof mode cannot receive replies\n\n"
            "Source spoofing (restricted to lab destination ranges):\n"
            "  --spoof-source      Allow a non-local source; requires root/network capability\n"
            "  --interface IFACE   Required output interface in spoof mode\n\n"
            "Payload controls:\n"
            "  --fill BYTE         Fill byte in decimal or 0xNN form (default: 0)\n"
            "  --stamp             Write ULG1, sequence and monotonic ns into first 16 bytes\n"
            "  --quiet             Suppress the startup description\n"
            "  -h, --help          Show this help\n",
            program, MAX_UDP_PAYLOAD);
}

static uint64_t parse_u64(const char *text, uint64_t max, const char *name)
{
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 0);
    if (errno != 0 || text[0] == '\0' || text[0] == '-' || end == NULL ||
        *end != '\0' || value > max) {
        fprintf(stderr, "Invalid %s: %s\n", name, text);
        exit(EXIT_FAILURE);
    }
    return (uint64_t)value;
}

static double parse_double(const char *text, const char *name)
{
    char *end = NULL;
    errno = 0;
    double value = strtod(text, &end);
    if (errno != 0 || text[0] == '\0' || end == NULL || *end != '\0' ||
        !isfinite(value) || value < 0.0) {
        fprintf(stderr, "Invalid %s: %s\n", name, text);
        exit(EXIT_FAILURE);
    }
    return value;
}

static struct options parse_options(int argc, char **argv)
{
    struct options opts = {
        .pps = 1000.0,
        .duration = 10.0,
        .fill = 0,
        .priority = UINT32_C(0x6e0001ff),
        .response_wait = 1.0,
    };
    bool have_src_port = false;
    bool have_dst_port = false;
    bool have_size = false;
    bool have_fill = false;
    bool have_pps = false;
    bool have_role = false;
    bool have_priority = false;
    bool have_response_wait = false;

    enum {
        OPT_SRC_IP = 1000,
        OPT_SRC_PORT,
        OPT_DST_IP,
        OPT_DST_PORT,
        OPT_SIZE,
        OPT_PPS,
        OPT_DURATION,
        OPT_COUNT,
        OPT_FILL,
        OPT_SNDBUF,
        OPT_SPOOF_SOURCE,
        OPT_INTERFACE,
        OPT_STAMP,
        OPT_QUIET,
        OPT_MODE,
        OPT_SENDER_UFRAG,
        OPT_TARGET_UFRAG,
        OPT_TARGET_PASSWORD,
        OPT_TARGET_PASSWORD_ENV,
        OPT_ROLE,
        OPT_PRIORITY,
        OPT_RESPONSE_WAIT,
        OPT_NO_RESPONSE_STATS,
    };
    static const struct option long_options[] = {
        {"src-ip", required_argument, NULL, OPT_SRC_IP},
        {"src-port", required_argument, NULL, OPT_SRC_PORT},
        {"dst-ip", required_argument, NULL, OPT_DST_IP},
        {"dst-port", required_argument, NULL, OPT_DST_PORT},
        {"size", required_argument, NULL, OPT_SIZE},
        {"pps", required_argument, NULL, OPT_PPS},
        {"duration", required_argument, NULL, OPT_DURATION},
        {"count", required_argument, NULL, OPT_COUNT},
        {"fill", required_argument, NULL, OPT_FILL},
        {"sndbuf", required_argument, NULL, OPT_SNDBUF},
        {"spoof-source", no_argument, NULL, OPT_SPOOF_SOURCE},
        {"interface", required_argument, NULL, OPT_INTERFACE},
        {"stamp", no_argument, NULL, OPT_STAMP},
        {"quiet", no_argument, NULL, OPT_QUIET},
        {"mode", required_argument, NULL, OPT_MODE},
        {"sender-ufrag", required_argument, NULL, OPT_SENDER_UFRAG},
        {"target-ufrag", required_argument, NULL, OPT_TARGET_UFRAG},
        {"target-password", required_argument, NULL, OPT_TARGET_PASSWORD},
        {"target-password-env", required_argument, NULL, OPT_TARGET_PASSWORD_ENV},
        {"role", required_argument, NULL, OPT_ROLE},
        {"priority", required_argument, NULL, OPT_PRIORITY},
        {"response-wait", required_argument, NULL, OPT_RESPONSE_WAIT},
        {"no-response-stats", no_argument, NULL, OPT_NO_RESPONSE_STATS},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
        switch (c) {
        case OPT_SRC_IP:
            opts.src_ip = optarg;
            break;
        case OPT_SRC_PORT:
            opts.src_port = (uint16_t)parse_u64(optarg, 65535, "source port");
            have_src_port = true;
            break;
        case OPT_DST_IP:
            opts.dst_ip = optarg;
            break;
        case OPT_DST_PORT:
            opts.dst_port = (uint16_t)parse_u64(optarg, 65535, "destination port");
            have_dst_port = true;
            break;
        case OPT_SIZE:
            opts.payload_size = (size_t)parse_u64(optarg, MAX_UDP_PAYLOAD, "size");
            have_size = true;
            break;
        case OPT_PPS:
            opts.pps = parse_double(optarg, "pps");
            have_pps = true;
            break;
        case OPT_DURATION:
            opts.duration = parse_double(optarg, "duration");
            break;
        case OPT_COUNT:
            opts.count = parse_u64(optarg, UINT64_MAX, "count");
            break;
        case OPT_FILL:
            opts.fill = (int)parse_u64(optarg, 255, "fill byte");
            have_fill = true;
            break;
        case OPT_SNDBUF:
            opts.sndbuf = (int)parse_u64(optarg, INT32_MAX, "send buffer");
            if (opts.sndbuf == 0) {
                fprintf(stderr, "Send buffer must be greater than zero.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case OPT_SPOOF_SOURCE:
            opts.spoof_source = true;
            break;
        case OPT_INTERFACE:
            opts.interface = optarg;
            break;
        case OPT_STAMP:
            opts.stamp = true;
            break;
        case OPT_QUIET:
            opts.quiet = true;
            break;
        case OPT_MODE:
            if (strcmp(optarg, "ice-binding") == 0) {
                opts.ice_binding = true;
            } else if (strcmp(optarg, "udp") == 0) {
                opts.ice_binding = false;
            } else {
                fprintf(stderr, "Invalid mode: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case OPT_SENDER_UFRAG:
            opts.sender_ufrag = optarg;
            break;
        case OPT_TARGET_UFRAG:
            opts.target_ufrag = optarg;
            break;
        case OPT_TARGET_PASSWORD:
            opts.target_password = optarg;
            break;
        case OPT_TARGET_PASSWORD_ENV:
            opts.target_password_env = optarg;
            break;
        case OPT_ROLE:
            if (strcmp(optarg, "controlling") == 0) {
                opts.controlling = true;
            } else if (strcmp(optarg, "controlled") == 0) {
                opts.controlling = false;
            } else {
                fprintf(stderr, "Invalid ICE role: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            have_role = true;
            break;
        case OPT_PRIORITY:
            opts.priority = (uint32_t)parse_u64(optarg, INT32_MAX, "ICE priority");
            have_priority = true;
            if (opts.priority == 0) {
                fputs("ICE priority must be greater than zero.\n", stderr);
                exit(EXIT_FAILURE);
            }
            break;
        case OPT_RESPONSE_WAIT:
            opts.response_wait = parse_double(optarg, "response wait");
            have_response_wait = true;
            if (opts.response_wait > 60.0) {
                fputs("Response wait must be 60 seconds or less.\n", stderr);
                exit(EXIT_FAILURE);
            }
            break;
        case OPT_NO_RESPONSE_STATS:
            opts.no_response_stats = true;
            break;
        case 'h':
            usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
        default:
            usage(stderr, argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (optind != argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        exit(EXIT_FAILURE);
    }
    if (opts.src_ip == NULL || opts.dst_ip == NULL || !have_src_port ||
        !have_dst_port || (!opts.ice_binding && !have_size)) {
        fputs("Missing a required option.\n\n", stderr);
        usage(stderr, argv[0]);
        exit(EXIT_FAILURE);
    }
    if (opts.dst_port == 0) {
        fputs("Destination port must be in the range 1-65535.\n", stderr);
        exit(EXIT_FAILURE);
    }
    if (opts.duration == 0.0 && opts.count == 0) {
        fputs("At least one of --duration or --count must be non-zero.\n", stderr);
        exit(EXIT_FAILURE);
    }
    if (opts.ice_binding) {
        if (have_size || have_fill || opts.stamp) {
            fputs("--size, --fill, and --stamp are not valid in ICE mode.\n", stderr);
            exit(EXIT_FAILURE);
        }
        if (opts.sender_ufrag == NULL || opts.target_ufrag == NULL || !have_role ||
            (opts.target_password == NULL && opts.target_password_env == NULL)) {
            fputs("ICE mode requires --sender-ufrag, --target-ufrag, "
                  "--role, and a target password.\n", stderr);
            exit(EXIT_FAILURE);
        }
        if (opts.target_password != NULL && opts.target_password_env != NULL) {
            fputs("Use only one of --target-password and --target-password-env.\n", stderr);
            exit(EXIT_FAILURE);
        }
        if (opts.target_password_env != NULL) {
            if (opts.target_password_env[0] == '\0') {
                fputs("Environment variable name cannot be empty.\n", stderr);
                exit(EXIT_FAILURE);
            }
            opts.target_password = getenv(opts.target_password_env);
            if (opts.target_password == NULL) {
                fprintf(stderr, "Environment variable is not set: %s\n",
                        opts.target_password_env);
                exit(EXIT_FAILURE);
            }
        }
        if (!have_pps) {
            opts.pps = 1.0;
        }
        if ((opts.spoof_source || opts.no_response_stats) && have_response_wait) {
            fputs("--response-wait requires ICE mode with response stats and "
                  "a non-spoofed source.\n", stderr);
            exit(EXIT_FAILURE);
        }
    } else if (opts.sender_ufrag != NULL || opts.target_ufrag != NULL ||
               opts.target_password != NULL || opts.target_password_env != NULL ||
               have_role || have_priority || have_response_wait ||
               opts.no_response_stats) {
        fputs("ICE-specific options require --mode ice-binding.\n", stderr);
        exit(EXIT_FAILURE);
    }
    if (opts.stamp && opts.payload_size < STAMP_SIZE) {
        fprintf(stderr, "--stamp requires --size of at least %u bytes.\n", STAMP_SIZE);
        exit(EXIT_FAILURE);
    }
    if (opts.spoof_source && opts.interface == NULL) {
        fputs("--spoof-source requires --interface.\n", stderr);
        exit(EXIT_FAILURE);
    }
    if (!opts.spoof_source && opts.interface != NULL) {
        fputs("--interface is only valid with --spoof-source.\n", stderr);
        exit(EXIT_FAILURE);
    }
    if (opts.interface != NULL && strlen(opts.interface) >= IFNAMSIZ) {
        fprintf(stderr, "Interface name is too long: %s\n", opts.interface);
        exit(EXIT_FAILURE);
    }

    return opts;
}

static struct in_addr parse_ipv4(const char *text, const char *name)
{
    struct in_addr address;
    if (inet_pton(AF_INET, text, &address) != 1) {
        fprintf(stderr, "Invalid %s IPv4 address: %s\n", name, text);
        exit(EXIT_FAILURE);
    }
    return address;
}

int main(int argc, char **argv)
{
    struct options opts = parse_options(argc, argv);
    struct stun_ice_config ice = {0};
    if (opts.ice_binding) {
        unsigned char random_tie_breaker[8];
        if (!random_bytes(random_tie_breaker, sizeof(random_tie_breaker))) {
            perror("getrandom(tie-breaker)");
            return EXIT_FAILURE;
        }
        uint64_t tie_breaker = 0;
        for (size_t i = 0; i < sizeof(random_tie_breaker); ++i) {
            tie_breaker = (tie_breaker << 8) | random_tie_breaker[i];
        }
        ice = (struct stun_ice_config){
            .sender_ufrag = opts.sender_ufrag,
            .target_ufrag = opts.target_ufrag,
            .target_password = opts.target_password,
            .priority = opts.priority,
            .tie_breaker = tie_breaker,
            .controlling = opts.controlling,
        };
        opts.payload_size = stun_ice_packet_size(&ice);
        if (opts.payload_size == 0 || opts.payload_size > MAX_UDP_PAYLOAD) {
            fputs("Invalid ICE credentials or STUN packet size. "
                  "Ufrags must be 4-256 ICE characters; password 1-256 bytes.\n",
                  stderr);
            return EXIT_FAILURE;
        }
    }
    struct sockaddr_in source = {
        .sin_family = AF_INET,
        .sin_port = htons(opts.src_port),
        .sin_addr = parse_ipv4(opts.src_ip, "source"),
    };
    struct sockaddr_in destination = {
        .sin_family = AF_INET,
        .sin_port = htons(opts.dst_port),
        .sin_addr = parse_ipv4(opts.dst_ip, "destination"),
    };

    if (opts.spoof_source && !is_unicast_source(source.sin_addr)) {
        fprintf(stderr, "Spoofed source must be a unicast IPv4 address: %s\n", opts.src_ip);
        return EXIT_FAILURE;
    }
    if (opts.spoof_source && !is_lab_destination(destination.sin_addr)) {
        fprintf(stderr,
                "Spoof mode only permits private, loopback, link-local, CGNAT, "
                "benchmark, or TEST-NET destinations: %s\n",
                opts.dst_ip);
        return EXIT_FAILURE;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    if (opts.sndbuf > 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opts.sndbuf, sizeof(opts.sndbuf)) != 0) {
        perror("setsockopt(SO_SNDBUF)");
        close(fd);
        return EXIT_FAILURE;
    }

    if (opts.spoof_source) {
        int enabled = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &enabled, sizeof(enabled)) != 0) {
            fprintf(stderr,
                    "Cannot enable source spoofing: %s\n"
                    "Run spoof mode as root or grant the required network capability.\n",
                    strerror(errno));
            close(fd);
            return EXIT_FAILURE;
        }
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                       opts.interface, strlen(opts.interface) + 1) != 0) {
            fprintf(stderr, "Cannot bind raw socket to interface %s: %s\n",
                    opts.interface, strerror(errno));
            close(fd);
            return EXIT_FAILURE;
        }
        int pmtu_mode = IP_PMTUDISC_DONT;
        if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
                       &pmtu_mode, sizeof(pmtu_mode)) != 0) {
            perror("setsockopt(IP_MTU_DISCOVER)");
            close(fd);
            return EXIT_FAILURE;
        }
    }

    if (bind(fd, (const struct sockaddr *)&source, sizeof(source)) != 0) {
        fprintf(stderr, "Cannot bind source %s:%u: %s\n",
                opts.src_ip, opts.src_port, strerror(errno));
        if (!opts.spoof_source) {
            fputs("The source address must be assigned to this machine.\n", stderr);
        }
        close(fd);
        return EXIT_FAILURE;
    }
    if (connect(fd, (const struct sockaddr *)&destination, sizeof(destination)) != 0) {
        fprintf(stderr, "Cannot connect UDP socket to %s:%u: %s\n",
                opts.dst_ip, opts.dst_port, strerror(errno));
        close(fd);
        return EXIT_FAILURE;
    }

    socklen_t source_len = sizeof(source);
    if (getsockname(fd, (struct sockaddr *)&source, &source_len) != 0) {
        perror("getsockname");
        close(fd);
        return EXIT_FAILURE;
    }

    char effective_src[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &source.sin_addr, effective_src, sizeof(effective_src)) == NULL) {
        perror("inet_ntop");
        close(fd);
        return EXIT_FAILURE;
    }

    size_t allocation_size = opts.payload_size == 0 ? 1 : opts.payload_size;
    unsigned char *payload = malloc(allocation_size);
    if (payload == NULL) {
        perror("malloc");
        close(fd);
        return EXIT_FAILURE;
    }
    if (!opts.ice_binding) {
        memset(payload, opts.fill, allocation_size);
    }

    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction");
        free(payload);
        close(fd);
        return EXIT_FAILURE;
    }

    bool collect_responses = opts.ice_binding && !opts.spoof_source &&
                             !opts.no_response_stats;
    struct response_tracker tracker = {0};
    if (collect_responses && !tracker_init(&tracker)) {
        perror("response tracker allocation");
        free(payload);
        close(fd);
        return EXIT_FAILURE;
    }

    if (!opts.quiet) {
        printf("UDP %s:%u -> %s:%u, payload=%zu bytes, mode=%s%s",
               effective_src, ntohs(source.sin_port), opts.dst_ip, opts.dst_port,
               opts.payload_size, opts.ice_binding ? "ice-binding" : "udp",
               opts.spoof_source ? "/spoof" : "");
        if (opts.spoof_source) {
            printf("(%s)", opts.interface);
        }
        printf(", pps=");
        if (opts.pps == 0.0) {
            printf("unlimited");
        } else {
            printf("%.3f", opts.pps);
        }
        printf(", duration=");
        if (opts.duration == 0.0) {
            printf("disabled");
        } else {
            printf("%.3fs", opts.duration);
        }
        if (opts.count != 0) {
            printf(", count=%" PRIu64, opts.count);
        }
        if (opts.ice_binding && !collect_responses) {
            printf(", response-stats=disabled");
        }
        putchar('\n');
    }

    uint64_t start_ns = monotonic_ns();
    uint64_t attempts = 0;
    uint64_t sent = 0;
    uint64_t errors = 0;
    uint64_t bytes = 0;

    while (!stop_requested) {
        uint64_t now_ns = monotonic_ns();
        if (opts.count != 0 && attempts >= opts.count) {
            break;
        }
        if (opts.duration > 0.0 &&
            (long double)(now_ns - start_ns) >= (long double)opts.duration * 1.0e9L) {
            break;
        }

        if (opts.pps > 0.0 && attempts > 0) {
            long double offset = (long double)attempts * 1.0e9L / (long double)opts.pps;
            uint64_t target_ns = start_ns + (uint64_t)offset;
            if (now_ns < target_ns) {
                if (collect_responses) {
                    wait_until_with_responses(fd, &tracker, opts.target_password,
                                              target_ns);
                } else {
                    sleep_until(target_ns);
                }
                if (stop_requested) {
                    break;
                }
                now_ns = monotonic_ns();
            }
            if (opts.duration > 0.0 &&
                (long double)(now_ns - start_ns) >= (long double)opts.duration * 1.0e9L) {
                break;
            }
        }

        unsigned char txid[12] = {0};
        if (opts.ice_binding) {
            if (!random_bytes(txid, sizeof(txid)) ||
                !stun_ice_build(&ice, txid, payload, opts.payload_size)) {
                fputs("Could not build ICE Binding Request.\n", stderr);
                ++errors;
                break;
            }
        } else if (opts.stamp) {
            put_stamp(payload, attempts, now_ns);
        }
        ssize_t result = send(fd, payload, opts.payload_size, 0);
        ++attempts;
        if (result == (ssize_t)opts.payload_size) {
            ++sent;
            bytes += opts.payload_size;
            if (collect_responses) {
                tracker_insert(&tracker, txid, monotonic_ns());
            }
        } else {
            ++errors;
            if (errors <= 5) {
                if (result < 0) {
                    fprintf(stderr, "send attempt %" PRIu64 ": %s\n",
                            attempts, strerror(errno));
                } else {
                    fprintf(stderr, "send attempt %" PRIu64 ": short packet (%zd/%zu)\n",
                            attempts, result, opts.payload_size);
                }
            }
        }
        if (collect_responses && attempts % 32U == 0) {
            drain_responses(fd, &tracker, opts.target_password, 256);
        }
    }

    uint64_t end_ns = monotonic_ns();
    if (collect_responses) {
        drain_responses(fd, &tracker, opts.target_password, 256);
        if (!stop_requested && tracker.active != 0 && opts.response_wait > 0.0) {
            uint64_t wait_ns = (uint64_t)(opts.response_wait * 1.0e9);
            wait_until_with_responses(fd, &tracker, opts.target_password,
                                      monotonic_ns() + wait_ns);
        }
        drain_responses(fd, &tracker, opts.target_password, 256);
    }
    double elapsed = (double)(end_ns - start_ns) / 1.0e9;
    double actual_pps = elapsed > 0.0 ? (double)sent / elapsed : 0.0;
    double mbps = elapsed > 0.0 ? (double)bytes * 8.0 / elapsed / 1000000.0 : 0.0;

    printf("sent=%" PRIu64 " attempted=%" PRIu64 " errors=%" PRIu64
           " bytes=%" PRIu64 " elapsed=%.6fs average=%.2fpps %.3fMbps\n",
           sent, attempts, errors, bytes, elapsed, actual_pps, mbps);

    if (collect_responses) {
        uint64_t received = tracker.success + tracker.error;
        printf("responses: success=%" PRIu64 " error=%" PRIu64
               " (401=%" PRIu64 " 487=%" PRIu64 " unauthenticated=%" PRIu64 ")"
               " unanswered=%" PRIu64 " (evicted=%" PRIu64 ")"
               " invalid=%" PRIu64 " unmatched=%" PRIu64
               " recv_errors=%" PRIu64 "\n",
               tracker.success, tracker.error, tracker.error_401, tracker.error_487,
               tracker.unauthenticated_error,
               (uint64_t)tracker.active + tracker.evicted, tracker.evicted,
               tracker.invalid, tracker.unmatched, tracker.receive_errors);
        if (received != 0) {
            printf("response_rtt_ms: min=%.3f avg=%.3f max=%.3f\n",
                   (double)tracker.rtt_min_ns / 1.0e6,
                   (double)(tracker.rtt_sum_ns / received) / 1.0e6,
                   (double)tracker.rtt_max_ns / 1.0e6);
        }
        free(tracker.pending);
        free(tracker.heads);
    }

    free(payload);
    close(fd);
    return errors == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
