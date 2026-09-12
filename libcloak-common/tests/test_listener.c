#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"
#include "test_framework.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void test_split_hostport(void) {
    char host[64];
    char port[16];

    ASSERT_EQ_INT(0, cloak_net_split_hostport("127.0.0.1:1984", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "127.0.0.1"));
    ASSERT_EQ_INT(0, strcmp(port, "1984"));

    /* an empty host means "every interface", the ":443" form Go's BindAddr uses */
    ASSERT_EQ_INT(0, cloak_net_split_hostport(":443", host, sizeof(host), port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, ""));
    ASSERT_EQ_INT(0, strcmp(port, "443"));

    /* bracketed IPv6 */
    ASSERT_EQ_INT(0, cloak_net_split_hostport("[::1]:443", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "::1"));
    ASSERT_EQ_INT(0, strcmp(port, "443"));

    ASSERT_EQ_INT(0, cloak_net_split_hostport("[::]:8080", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "::"));
    ASSERT_EQ_INT(0, strcmp(port, "8080"));

    /* a hostname, not an address */
    ASSERT_EQ_INT(0, cloak_net_split_hostport("localhost:51443", host, sizeof(host),
                                              port, sizeof(port)));
    ASSERT_EQ_INT(0, strcmp(host, "localhost"));
    ASSERT_EQ_INT(0, strcmp(port, "51443"));

    /* rejections */
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("no-port", host, sizeof(host),
                                               port, sizeof(port)));
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("", host, sizeof(host), port, sizeof(port)));
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("host:", host, sizeof(host),
                                               port, sizeof(port)));
    /* unbracketed IPv6 is ambiguous and rejected, matching Go's net.SplitHostPort */
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("::1:443", host, sizeof(host),
                                               port, sizeof(port)));
    /* a host that does not fit */
    char tiny[4];
    ASSERT_EQ_INT(-1, cloak_net_split_hostport("127.0.0.1:1984", tiny, sizeof(tiny),
                                               port, sizeof(port)));
}

struct accept_capture {
    cloak_reactor_t *reactor;
    int accepted_fd;
    int accept_count;
    char first_byte;
};

static void on_accept(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    struct accept_capture *cap = userdata;
    cap->accept_count++;
    cap->accepted_fd = fd;

    /* read the byte the client sent, to prove this is the same connection */
    char c = 0;
    ssize_t n = read(fd, &c, 1);
    if (n == 1) {
        cap->first_byte = c;
    }
    cloak_reactor_stop(cap->reactor);
}

/* Connects to 127.0.0.1:port with a blocking socket and sends one byte. */
static int connect_and_send(int port, char byte) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (write(fd, &byte, 1) != 1) {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_accepts_a_connection(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct accept_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.accepted_fd = -1;

    cloak_listener_t l;
    char err[128] = {0};
    /* port 0 asks the kernel for a free port */
    ASSERT_EQ_INT(0, cloak_listener_open(&l, r, "127.0.0.1:0", on_accept, &cap,
                                         err, sizeof(err)));

    int port = cloak_listener_port(&l);
    ASSERT_TRUE(port > 0);

    int client = connect_and_send(port, 'Q');
    ASSERT_TRUE(client >= 0);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(1, cap.accept_count);
    ASSERT_TRUE(cap.accepted_fd >= 0);
    ASSERT_EQ_INT('Q', cap.first_byte);

    if (cap.accepted_fd >= 0) {
        close(cap.accepted_fd);
    }
    if (client >= 0) {
        close(client);
    }
    cloak_listener_close(&l);
    cloak_reactor_destroy(r);
}

struct multi_capture {
    cloak_reactor_t *reactor;
    int accept_count;
    int fds[4];
};

static void on_accept_multi(cloak_listener_t *l, int fd, void *userdata) {
    (void)l;
    struct multi_capture *cap = userdata;
    if (cap->accept_count < 4) {
        cap->fds[cap->accept_count] = fd;
    }
    cap->accept_count++;
    if (cap->accept_count == 3) {
        cloak_reactor_stop(cap->reactor);
    }
}

static void test_drains_all_pending_connections(void) {
    /* The reactor is edge-triggered: if the accept callback stops after one
     * accept, the two connections that arrived in the same edge are never
     * reported. This is the test that catches that. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct multi_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;

    cloak_listener_t l;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_listener_open(&l, r, "127.0.0.1:0", on_accept_multi, &cap,
                                         err, sizeof(err)));
    int port = cloak_listener_port(&l);
    ASSERT_TRUE(port > 0);

    int clients[3];
    for (int i = 0; i < 3; i++) {
        clients[i] = connect_and_send(port, (char)('a' + i));
        ASSERT_TRUE(clients[i] >= 0);
    }

    cloak_reactor_run(r);
    ASSERT_EQ_INT(3, cap.accept_count);

    for (int i = 0; i < 3; i++) {
        if (cap.fds[i] >= 0) {
            close(cap.fds[i]);
        }
        close(clients[i]);
    }
    cloak_listener_close(&l);
    cloak_reactor_destroy(r);
}

static void test_open_rejects_bad_input(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }
    cloak_listener_t l;
    char err[128];

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_listener_open(&l, r, "not-an-address", on_accept, NULL,
                                          err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');

    /* port 1 is privileged: binding it as a normal user fails. Skip the
     * assertion when running as root, where it would succeed. */
    if (geteuid() != 0) {
        err[0] = '\0';
        ASSERT_EQ_INT(-1, cloak_listener_open(&l, r, "127.0.0.1:1", on_accept, NULL,
                                              err, sizeof(err)));
        ASSERT_TRUE(err[0] != '\0');
    }

    cloak_reactor_destroy(r);
}

static void test_two_listeners_on_one_reactor(void) {
    /* The server binds every entry in BindAddr, so two listeners must
     * coexist on one reactor without confusing each other's callbacks. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    struct accept_capture cap_a;
    struct accept_capture cap_b;
    memset(&cap_a, 0, sizeof(cap_a));
    memset(&cap_b, 0, sizeof(cap_b));
    cap_a.reactor = r;
    cap_b.reactor = r;
    cap_a.accepted_fd = -1;
    cap_b.accepted_fd = -1;

    cloak_listener_t la;
    cloak_listener_t lb;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_listener_open(&la, r, "127.0.0.1:0", on_accept, &cap_a,
                                         err, sizeof(err)));
    ASSERT_EQ_INT(0, cloak_listener_open(&lb, r, "127.0.0.1:0", on_accept, &cap_b,
                                         err, sizeof(err)));
    ASSERT_TRUE(cloak_listener_port(&la) != cloak_listener_port(&lb));

    int client = connect_and_send(cloak_listener_port(&lb), 'B');
    ASSERT_TRUE(client >= 0);
    cloak_reactor_run(r);

    ASSERT_EQ_INT(0, cap_a.accept_count);
    ASSERT_EQ_INT(1, cap_b.accept_count);
    ASSERT_EQ_INT('B', cap_b.first_byte);

    if (cap_b.accepted_fd >= 0) {
        close(cap_b.accepted_fd);
    }
    close(client);
    cloak_listener_close(&la);
    cloak_listener_close(&lb);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_split_hostport();
    test_accepts_a_connection();
    test_drains_all_pending_connections();
    test_open_rejects_bad_input();
    test_two_listeners_on_one_reactor();
TEST_MAIN_END()
