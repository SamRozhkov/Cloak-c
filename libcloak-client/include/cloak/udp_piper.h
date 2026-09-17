#ifndef CLOAK_UDP_PIPER_H
#define CLOAK_UDP_PIPER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/stream.h"

/* THE CLIENT'S UDP LOCAL LISTENER: one datagram socket, many peers, one
 * unordered stream per peer. Go's RouteUDP (internal/client/piper.go:15-100)
 * does the same job with one `*net.UDPConn`, a map keyed by
 * `addr.String()`, and one stream plus one reader goroutine per source
 * address.
 *
 * IT IS NOT cloak_client_piper_t WITH A DIFFERENT SOCKET TYPE, and the
 * reason is worth stating first because the shape of everything below
 * follows from it. cloak_client_piper_t gets one DESCRIPTOR per local
 * connection out of cloak_listener_open's accept(2), so it can hand each
 * one to a cloak_stream_relay_t, which owns an fd, registers it, pauses
 * ITS OWN read interest under backpressure and closes it at the end. Here
 * there is exactly ONE descriptor for every peer that will ever exist, so
 * none of that is available:
 *
 *   - NO RELAY. cloak_stream_relay_t assumes an exclusive fd -- it
 *     deregisters and closes it on teardown -- and a peer retiring must
 *     not deregister or close the socket every other peer is using. So
 *     this module does its own pumping, and cloak_stream_relay_t is the
 *     object it deliberately does not reuse (its shape and its contracts
 *     are still the model: one teardown path, a done-ish walk driven by
 *     several entry points, notifications forwarded in from the session,
 *     and a read budget derived from the pool before every read).
 *   - NO PER-PEER READ INTEREST. Read interest is a property of the one
 *     socket. Dropping it because ONE peer is backed up would stop
 *     reading datagrams addressed to every other peer -- and, worse,
 *     would be indistinguishable from progress: the datagrams keep
 *     arriving in the kernel's receive buffer and are then dropped by the
 *     kernel, for everybody, because of one slow peer. So the inbound
 *     direction is paused only for a SESSION-WIDE reason (the outbound
 *     pool has no room for one more frame), never for a per-peer one.
 *   - NO BLOCKING, ANYWHERE. Go gives each peer a goroutine and lets it
 *     block in localConn.WriteTo and in datagramBufferedPipe.Write. A
 *     single-threaded reactor cannot stall one peer without stalling all
 *     of them, which is where D5 below comes from.
 *
 * ---- D5: A FULL PER-PEER DATAGRAM QUEUE DROPS THE NEWEST ---------------
 *
 * THE ONE DECLARED DIVERGENCE FROM GO ON THIS PATH, and no test against
 * Go can adjudicate it: Go does not have this state at all. Its
 * datagramBufferedPipe.Write BLOCKS the writing goroutine until the
 * peer's reader makes room (datagramBufferedPipe.go:72-81) -- which on
 * the client means blocking the connection's whole receive loop, i.e.
 * stalling every OTHER peer's stream on that connection until one slow
 * peer catches up.
 *
 * This port drops instead, and drops the INCOMING datagram -- the newest.
 * The plan's Ruling 2 settled which, and the reasons are:
 *
 *   - nothing already accepted is ever discarded, so a datagram
 *     acknowledged to the reactor cannot vanish later;
 *   - it is what a full socket receive buffer does, which is the
 *     behaviour a UDP application is already written against;
 *   - it needs no queue surgery, and on a single-threaded reactor that
 *     means no partial-state window.
 *
 * THE DROP HAPPENS ONE LAYER DOWN, NOT HERE. cloak_stream_feed_frame
 * performs it (cloak/stream.h, cloak_stream_t::recv_dropped_datagrams)
 * and returns 0, deliberately, so that transient backpressure does not
 * retire a live stream. This module is that counter's FIRST READER:
 * cloak_udp_piper_dropped_datagrams sums it over every live peer plus
 * every peer already retired, because a per-stream counter dies with its
 * stream and an operator asking "is this tunnel losing datagrams" cannot
 * be answered by a number that resets.
 *
 * WHAT FILLS THAT QUEUE, since the whole divergence is unreachable
 * without it: this module pops at most ONE datagram from a peer's stream
 * at a time and holds it until sendto(2) accepts it. While one is held,
 * that peer's stream is not drained, so further frames for that peer pile
 * up in ITS OWN queue and are dropped there when it is full -- per peer,
 * with no effect on any other peer's stream, which is exactly the
 * property Go's blocking model does not have.
 *
 * ---- SEND BACKPRESSURE ON A DATAGRAM SOCKET IS PER DESTINATION --------
 *
 * AND THAT IS WHY A TIMER, NOT WRITABILITY, RESUMES IT. This is the
 * single least obvious thing in this file.
 *
 * On a connected stream socket, EAGAIN from a write means "this
 * socket's buffer is full" and epoll's WRITABLE edge is exactly the
 * signal that it no longer is. On a datagram socket sending to many
 * destinations, EAGAIN can mean something epoll cannot see: for an
 * AF_UNIX SOCK_DGRAM peer it means THE DESTINATION's receive queue is
 * full (unix_dgram_sendmsg's unix_recvq_full check), which is a property
 * of another socket entirely -- ours stays writable throughout. A
 * WRITABLE registration would therefore fire immediately and forever
 * without the condition having changed, which is a spin, not a resume.
 *
 * So a peer whose sendto was refused arms its own retry timer
 * (cloak_udp_piper_config_t::send_retry_delay_ms). This is the same
 * argument cloak_stream_relay_t's rate_timer makes for the rate-limited
 * case -- "resumed by nothing whatsoever: no queue drains, the readiness
 * edge is already spent, and the peer has no reason to act; only the
 * clock changes" -- and the same consequence: a stalled send with no
 * timer behind it is a peer that holds a stream and never moves another
 * byte, indistinguishable from a working one.
 *
 * MEASURED, because the reachability of that state is not obvious and it
 * decides how this module can be tested at all (probe run in the project
 * image, and the numbers are cited by libcloak-client/tests/test_udp_piper.c,
 * which fails if the AF_UNIX half stops holding):
 *   AF_INET UDP over loopback: SO_SNDBUF 4096, receiver SO_RCVBUF 1024,
 *     20000 sends of 1024 bytes -- ZERO failures. Loopback frees the skb
 *     as soon as the receiving socket accepts or drops it, so a UDP send
 *     on loopback essentially never reports backpressure; the loss
 *     happens silently at the receiver instead.
 *   AF_UNIX SOCK_DGRAM: receiver SO_RCVBUF 4096, sends of 1024 bytes --
 *     EAGAIN at the 11th send, and the very next send after the receiver
 *     drained one datagram succeeded.
 * The retry timer exists for both; only the second can be provoked, which
 * is why cloak_udp_piper_adopt exists (see it).
 *
 * ---- SIZES: D7, AND WHERE FIDELITY AND CORRECTNESS PART ---------------
 *
 * Four sizes, three of which Go gets wrong (scouting report §6.6, bugs 6
 * and 7, measured against ck-client v2.12.0):
 *
 *   > one frame's payload, OUTBOUND (local -> stream): REFUSED, exactly
 *     as Go refuses it (io.ErrShortBuffer). The datagram is dropped and
 *     counted (cloak_udp_piper_oversize_datagrams). Splitting it would be
 *     silent corruption -- the far end does no reassembly in this mode.
 *     The boundary is not a literal here: it is the stream's own
 *     max_payload_per_frame, which cloak/stream.h derives as
 *     max_on_wire_size - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN
 *     (16132 at the 16401 both ends use).
 *   8193..16132, EITHER DIRECTION: CARRIED. Go loses these AND tears the
 *     peer's stream down doing it, in both directions, for two different
 *     reasons: its local read buffer is 8192 bytes so a larger datagram
 *     from the application is silently TRUNCATED (piper.go:25, bug 7),
 *     and its reader goroutine's buffer is 8192 too, so a larger reply
 *     produces io.ErrShortBuffer, which its `if err != nil { break }`
 *     treats exactly like EOF (bug 6).
 *   ZERO-LENGTH: SWALLOWED, matching Go. Go's Stream.Write loop
 *     (`for n < len(in)`) never runs for an empty input and returns
 *     (0, nil), and its frame encoder refuses an empty payload outright
 *     (obfs.go:65-67) -- as does cloak_frame_obfuscate -- so carrying one
 *     was never reachable at either end. Counted
 *     (cloak_udp_piper_empty_datagrams) rather than silently ignored,
 *     because a zero-length datagram is a real thing an application can
 *     send and "it vanished" is otherwise undiagnosable.
 *
 * THE TWO HAZARDS THIS MODULE HAD TO AVOID RATHER THAN INHERIT, both
 * visible in libcloak-mux/src/stream_relay.c, both the same bug in
 * opposite directions, and neither reachable from here:
 *
 *   READ SIDE. cloak_stream_read's CLOAK_STREAM_ERR_SHORT_BUFFER (-2)
 *     means "your buffer was too small, THE DATAGRAM IS STILL QUEUED",
 *     and a reader that treats it as end-of-stream ends a live stream
 *     over transient backpressure -- Go's bug 6, in C. This module's
 *     per-peer read buffer is sized from the stream's own
 *     max_payload_per_frame, so no datagram the stream can legally hold
 *     can ever be larger than it and -2 is structurally unreachable. It
 *     is still handled, and handled as "stop draining for now", never as
 *     EOF.
 *   WRITE SIDE. cloak_stream_write REFUSES (-2 again) a datagram larger
 *     than max_payload_per_frame, and a caller that reads any negative as
 *     fatal kills the stream over one oversized datagram. This module
 *     reads the local socket with MSG_TRUNC into a buffer of exactly
 *     max_payload_per_frame, so an oversized datagram is identified
 *     BEFORE the write (recvmsg reports the true length even when it
 *     truncated) and dropped on its own, leaving the peer alive. The
 *     write is therefore never handed more than one frame's payload, and
 *     -2 cannot come back from it either.
 *
 * ---- PEER LIFETIME ----------------------------------------------------
 *
 * A peer exists from its first datagram until its deadline expires, its
 * stream ends, or the piper/session goes away. THE DEADLINE IS GO'S:
 * RouteUDP sets a read deadline of streamTimeout on the stream and
 * refreshes it on every datagram in EITHER direction; when it expires the
 * reader goroutine's Read fails, it deletes its own key and closes its
 * stream. cloak_udp_piper_config_t::peer_timeout_ms is that quantity,
 * refreshed at exactly the same four points (see the field).
 *
 * WHAT A PEER COSTS, since nothing about a UDP source address is
 * authenticated and anything that can reach the local socket can invent
 * one: one stream id on the session, one heap context with one
 * max_payload_per_frame buffer, one timer -- and nothing on the server
 * until a frame is actually sent, because cloak_session_open_stream is
 * local. cloak_udp_piper_config_t::max_peers bounds the count; the
 * deadline bounds the time. Go bounds neither.
 *
 * SINGLEPLEX IS NOT IMPLEMENTED HERE, and is refused by
 * cloak_client_stack_open rather than silently ignored. Go's RouteUDP
 * supports it (a session per peer). The seam it needs is
 * cloak_client_piper_t's new_session/cancel_session pair, and the extra
 * state a UDP peer needs that a TCP one does not is a buffered first
 * DATAGRAM -- a TCP connection's unread bytes can be left in the kernel
 * behind an MSG_PEEK, which is how cloak_client_piper_t avoids buffering
 * anything during a bring-up, and a shared datagram socket has no such
 * place to leave them without blocking every other peer. Stated as a gap
 * rather than half-built.
 *
 * LIFETIME: like every reactor-driven object here, the piper and each
 * peer must stay at a fixed address until their terminal event -- both
 * are callback userdata. Peers are heap-allocated and never moved. THE
 * PIPER MUST BE DESTROYED BEFORE THE SESSION IT WAS GIVEN, for the same
 * reason cloak_client_piper_t must: cloak_udp_piper_destroy is what
 * releases the streams, and a stream may only be released to a live
 * session.
 *
 * THREADING: none, like everything else in this project. */

typedef struct cloak_udp_piper cloak_udp_piper_t;

/* How long a peer may be silent before its stream is retired. Go's
 * ck-client StreamTimeout, 300 seconds by default
 * (internal/client/state.go), applied by RouteUDP as a read deadline on
 * the stream and refreshed on every datagram in either direction.
 *
 * Much smaller and a legitimate low-rate flow -- a DNS resolver, a VPN
 * keepalive, a game client between rounds -- has its tunnel torn out from
 * under it and the next datagram silently starts a new stream, which on
 * the server is a new upstream socket and a new source port. Much larger,
 * or absent, and every source address that ever sent one datagram pins a
 * stream and a buffer forever. The same value as
 * CLOAK_CLIENT_PIPER_DEFAULT_FIRST_BYTE_TIMEOUT_MS, and from the same
 * config field, so the two local listeners cannot disagree about what
 * StreamTimeout means. */
#define CLOAK_UDP_PIPER_DEFAULT_PEER_TIMEOUT_MS ((uint64_t)300000)

/* The most peers held at once. Over it, the datagram is dropped and
 * counted (cloak_udp_piper_refused_peers) and nothing else happens -- no
 * stream, no context, no effect on any peer already running.
 *
 * WHY A CAP AT ALL, given Go has none: a UDP source address is
 * unauthenticated and costs the sender nothing to change, so without a
 * cap anything that can reach the local socket can make this client open
 * an unbounded number of streams by varying its source port -- one
 * sendto(2) each. That is cheaper than the TCP piper's equivalent (which
 * needs a connect(2) and a descriptor per peer) by exactly the cost of
 * the handshake, which is to say entirely. 256 matches
 * CLOAK_CLIENT_PIPER_DEFAULT_MAX_LOCAL_CONNS deliberately: the two local
 * listeners bound the same resource for the same reason, and an operator
 * should not have to learn two numbers. */
#define CLOAK_UDP_PIPER_DEFAULT_MAX_PEERS ((size_t)256)

/* How long to wait before re-attempting a sendto(2) that was refused with
 * EAGAIN/ENOBUFS. See this file's PER DESTINATION section for why this is
 * a timer and not a WRITABLE registration.
 *
 * 10 ms is a latency/CPU trade with no oracle behind it: a refused
 * datagram is delayed by up to this much, and a peer that stays refused
 * costs one timer firing per interval for as long as it does. Much
 * smaller and a wedged peer spins the reactor; much larger and a
 * momentary receive-queue full costs a visible stall on a path whose
 * whole point is latency. There is no retry CEILING -- the peer deadline
 * is the bound, and it is the right one: a peer that cannot be sent to
 * and never sends anything either is retired by it, and a peer that keeps
 * sending is one this client would be wrong to forget. */
#define CLOAK_UDP_PIPER_DEFAULT_SEND_RETRY_MS ((uint64_t)10)

/* Datagrams the local socket's read loop will take in ONE entry before
 * re-arming and returning to the reactor. See
 * cloak_udp_piper_datagrams_read for why a bound is needed at all -- in
 * short, neither of the loop's two previous exits (EAGAIN and the
 * outbound pool) bounds a turn on a healthy link, and the datagrams this
 * module drops rather than forwards bound nothing at all.
 *
 * 32 IS CHOSEN, NOT MEASURED, and saying so is cheaper than implying an
 * oracle that does not exist: there is no Go number to match (Go reads
 * each peer in a goroutine of its own, with no budget), and no throughput
 * target was measured against it. What the value has to be is FINITE and
 * large enough that the re-arm is not paid per datagram; 32 datagrams is
 * up to half a megabyte of application payload per turn at the shipping
 * max_on_wire_size, which is far above any real local proxy's burst, and
 * one extra epoll_ctl per 32 datagrams is not a cost worth tuning.
 *
 * It is pinned EXACTLY -- not as a bound -- by test_udp_piper.c's
 * test_the_read_loop_yields_after_its_budget, which spells 32 as a
 * literal so that a change here is a failing test and therefore a
 * deliberate act. */
#define CLOAK_UDP_PIPER_READ_BUDGET ((unsigned)32)

/* Streams THE SERVER may open toward this client, and have refused,
 * before the session is closed outright. Identical in value and in
 * argument to CLOAK_CLIENT_PIPER_MAX_REJECTED_STREAMS -- see
 * cloak/client_piper.h, which carries the full reasoning: every stream in
 * this protocol is client-initiated, refusing is right, refusing forever
 * is a one-to-one amplification of permanent cloak_strmtab_t tombstones,
 * and the server could close the session itself at any time anyway. */
#define CLOAK_UDP_PIPER_MAX_REJECTED_STREAMS ((size_t)16)

/* ONE PEER: one source address, one stream, one in-flight datagram.
 *
 * Heap-allocated and never moved -- its address is the userdata for its
 * own two timers. */
typedef struct cloak_udp_piper_peer {
    cloak_udp_piper_t *pp;

    /* THE KEY. Go's map is keyed by addr.String(); this compares the
     * address itself, field by field per family, rather than memcmp'ing
     * the sockaddr_storage -- see udp_piper.c's peer_addr_equal for the
     * two padding fields (sin_zero, sin6_flowinfo) that are not part of a
     * peer's identity and would make two datagrams from the same peer
     * look like two peers if they were. */
    struct sockaddr_storage addr;
    socklen_t addr_len;

    /* The session this peer's stream lives on. BORROWED, and NULL is not
     * a reachable state on a live peer: a peer is created only when a
     * session exists, and piper_on_broken tears every peer bound to a
     * dying session down rather than clearing this. */
    cloak_session_t *sesh;
    cloak_stream_t *stream; /* owned by the session; released by us */

    /* ONE datagram popped from the stream and not yet accepted by
     * sendto(2), and the whole of this module's outbound queue. out_len
     * == 0 means nothing is pending; while it is non-zero the peer's
     * stream is deliberately NOT drained, which is what makes D5's
     * per-peer backlog land in that peer's own datagram queue. Capacity
     * is the stream's max_payload_per_frame, which is why
     * cloak_stream_read can never answer CLOAK_STREAM_ERR_SHORT_BUFFER
     * here. */
    uint8_t *out;
    size_t out_cap;
    size_t out_len;

    /* Armed only while out_len > 0 and the last sendto was refused. */
    cloak_timer_id_t send_timer;

    /* Go's stream read deadline. last_activity_ms is refreshed on every
     * datagram in either direction and `deadline` is a LAZY timer: when
     * it fires it re-checks the clock and re-arms for the remainder if
     * the peer has spoken since. That costs at most one extra firing per
     * timeout period and makes refreshing the deadline a single store,
     * rather than a cancel plus an add on the hot path -- which, at one
     * datagram per timer pair, is what a VPN peer's traffic would
     * actually be doing all day. */
    uint64_t last_activity_ms;
    cloak_timer_id_t deadline;

    struct cloak_udp_piper_peer *prev, *next;
} cloak_udp_piper_peer_t;

/* reactor is borrowed, not owned, and must outlive the piper. Each sizing
 * field defaults (0 means "use the default") to the matching
 * CLOAK_UDP_PIPER_DEFAULT_* above. */
typedef struct {
    cloak_reactor_t *reactor;

    /* Go's StreamTimeout. 0 -> CLOAK_UDP_PIPER_DEFAULT_PEER_TIMEOUT_MS.
     *
     * REFRESHED AT EXACTLY FOUR POINTS, which is Go's own set: a datagram
     * read from the local socket for this peer, a datagram written into
     * this peer's stream, a datagram read out of this peer's stream, and
     * a datagram accepted by sendto for this peer. NOT refreshed by a
     * REFUSED sendto, and that is the difference between a bound and a
     * decoration: a peer that can neither receive nor send would
     * otherwise keep its own deadline alive by failing, forever. */
    uint64_t peer_timeout_ms;

    size_t max_peers;            /* 0 -> ..._DEFAULT_MAX_PEERS */
    uint64_t send_retry_delay_ms;/* 0 -> ..._DEFAULT_SEND_RETRY_MS */

    /* OPTIONAL, and the reason this module can afford to BE the session's
     * on_broken: an owner with bookkeeping of its own installs it here
     * and gets it invoked with its own userdata AFTER this module's
     * cleanup has completed. The ordering is not negotiable, for the
     * reason cloak/client_piper.h gives for its own chain: a callback in
     * that position may call cloak_session_destroy, and by then every
     * stream this piper held must already be released. */
    cloak_session_broken_cb chain;
    void *chain_userdata;
} cloak_udp_piper_config_t;

struct cloak_udp_piper {
    cloak_udp_piper_config_t cfg; /* copied by value, defaults filled in */

    /* THE one socket. -1 whenever this module holds none. */
    int fd;
    int fd_registered;
    int port; /* the bound port, or -1 -- see cloak_udp_piper_port */
    uint32_t interest;

    /* 1 while read interest has been dropped because the session's
     * outbound pool cannot hold one more worst-case frame. SESSION-WIDE,
     * never per peer: see this file's opening. Resumed by
     * cloak_udp_piper_notify_writable, which the session's on_writable
     * drives. */
    int read_paused;

    /* 1 while the socket's read loop is running. The loop calls
     * cloak_stream_write, which cloak/session.h permits to fire
     * on_writable SYNCHRONOUSLY -- and this module's on_writable resumes
     * a paused read by pumping. Without this flag that resume would start
     * a SECOND read loop over the same socket from inside the first, with
     * two stack frames each believing they own the recvfrom sequence and
     * each able to retire a peer the other is holding. The loop re-derives
     * its budget every iteration, so clearing read_paused is all a nested
     * resume ever needed to do. */
    int in_read_loop;

    /* The shared session every peer's stream is opened on, or NULL before
     * one has been set and after the one that was has broken. Unlike
     * cloak_client_piper_t this IS dereferenced (to open streams and to
     * measure the pool), because there is no per-connection accept
     * callback to copy it in -- but only ever after a NULL check, and a
     * peer's own ->sesh is what every peer-scoped operation uses. */
    cloak_session_t *sesh;

    cloak_udp_piper_peer_t *peers;
    size_t peer_count;

    /* Lifetime totals. None of them ever falls. */
    size_t peers_created;
    size_t peers_expired;   /* retired by the deadline specifically */
    size_t refused_peers;   /* datagrams from a new peer with no room or no session */
    size_t rejected_streams;/* the server opened a stream toward us */
    size_t shared_rejected_streams; /* the CURRENT session's own count -- the ceiling */
    uint64_t oversize_datagrams;
    uint64_t empty_datagrams;
    uint64_t send_stalls;   /* sendto refusals, not peers */
    uint64_t pool_pauses;   /* times the local socket's read interest was dropped */
    uint64_t datagrams_read;/* datagrams taken off the local socket, whatever became of them */
    uint64_t read_yields;   /* times the read loop stopped on its per-turn budget */

    /* recv_dropped_datagrams harvested from streams that have already
     * been released, so that cloak_udp_piper_dropped_datagrams can be a
     * lifetime total rather than a number that falls when a peer retires. */
    uint64_t retired_dropped;

    int logged_refused_peer;
    int logged_rejected_stream;
    int logged_dropped;
};

/* Zeroes pp and validates the rest -- IN THAT ORDER, so any failure
 * return still leaves pp safe to pass to cloak_udp_piper_destroy.
 *
 * No socket is opened, no reactor registration is made and no timer is
 * armed. Returns 0, or -1 if pp, cfg or cfg->reactor is NULL. */
int cloak_udp_piper_init(cloak_udp_piper_t *pp, const cloak_udp_piper_config_t *cfg);

/* Installs this module's four session callbacks into *config with pp as
 * all four userdata values. Call it on the session TEMPLATE before the
 * session is created, exactly as cloak_client_piper_install is called.
 *
 * ALL FOUR, none optional:
 *   on_new_stream   -- refuses it (see cloak_udp_piper_rejected_streams).
 *   on_stream_data  -- routes the frame to the right peer and drains it.
 *   on_writable     -- resumes a read paused by a full outbound pool.
 *   on_broken       -- releases every stream in the one window where that
 *                      is still possible, then calls cfg.chain.
 * A no-op on a NULL pp or config. */
void cloak_udp_piper_install(cloak_udp_piper_t *pp, cloak_session_config_t *config);

/* Points the piper at the live session peers will be opened on. Until
 * this is called (and after the session it was given has broken) an
 * arriving datagram from an unknown peer is dropped and counted as a
 * refused peer -- there is nothing to open a stream on, and a UDP sender
 * has no connection to be refused on.
 *
 * sesh is BORROWED: this module opens, releases and reads streams on it
 * and never closes or destroys it. Passing NULL detaches, which is what
 * the broken walk does internally; it does NOT tear down peers, for the
 * same reason cloak_client_piper_set_session does not (a detach for an
 * already-dead session must be preceded by the walk, because a stream can
 * only be released while its session lives). Call cloak_udp_piper_destroy
 * for that.
 *
 * It resets the CURRENT session's refusal budget and its one log line,
 * because those are scoped to a session; the lifetime total is not
 * reset. */
void cloak_udp_piper_set_session(cloak_udp_piper_t *pp, cloak_session_t *sesh);

/* Binds a UDP socket on addr ("host:port", the forms
 * cloak_net_split_hostport accepts; port 0 asks the kernel to choose one,
 * readable afterwards via cloak_udp_piper_port), makes it non-blocking,
 * registers it for reading and starts routing.
 *
 * SO_REUSEADDR is set for the same reason cloak_listener_open sets it: a
 * restart should not have to wait out a stale binding. Returns 0, or -1
 * with the reason in err (which may be NULL) on a NULL argument, a
 * malformed or unresolvable address, a socket/bind failure, or a reactor
 * registration failure. On failure pp holds no descriptor and is safe to
 * destroy. Calling it twice on one piper is rejected. */
int cloak_udp_piper_open(cloak_udp_piper_t *pp, const char *addr, char *err, size_t err_cap);

/* Adopts an already-bound datagram socket instead of opening one: pp
 * takes ownership of fd (it is closed by cloak_udp_piper_destroy),
 * registers it for reading and starts routing. fd must be a bound
 * SOCK_DGRAM socket; it is set non-blocking here rather than assumed to
 * be.
 *
 * WHY THIS IS PUBLIC, stated plainly because a seam that exists for tests
 * should say so: D5 -- the whole declared divergence this module is built
 * around -- only happens when sendto(2) refuses a datagram, and MEASURED
 * IN THIS PROJECT'S OWN IMAGE, an AF_INET UDP socket on loopback does not
 * refuse: 20000 sends of 1024 bytes with SO_SNDBUF 4096 into a receiver
 * with SO_RCVBUF 1024 produced zero failures, because loopback frees the
 * skb the instant the receiver accepts or drops it. An AF_UNIX SOCK_DGRAM
 * socket does refuse, deterministically (EAGAIN at the 11th such send
 * into a receiver with SO_RCVBUF 4096) and recovers when the receiver
 * drains. Nothing in this module is AF_INET-specific -- a peer is a
 * sockaddr and a datagram is a datagram -- so adopting a socket of
 * another family is how the divergence is made assertable at all. It is
 * also the entry point for a caller that binds with options this module
 * does not model (SO_REUSEPORT, a bound device, a socket inherited from a
 * supervisor).
 *
 * Returns 0, or -1 on a NULL pp, an fd < 0, a piper that already has one,
 * or a fcntl/reactor failure -- on which the CALLER still owns fd, the
 * same uniform rule cloak_stream_relay_start states (every failure path
 * here deregisters before unwinding so there is no exception to it). */
int cloak_udp_piper_adopt(cloak_udp_piper_t *pp, int fd);

/* The bound port, or -1 if this piper has no socket or its socket has no
 * port (an AF_UNIX one). */
int cloak_udp_piper_port(const cloak_udp_piper_t *pp);

/* Retires every peer -- cancelling both of its timers, releasing its
 * stream back to its session and freeing it -- then unregisters and
 * closes the socket.
 *
 * MUST RUN BEFORE cloak_session_destroy ON THE SESSION IT WAS GIVEN: a
 * stream can only be released to a live session, and cloak/session.h
 * requires exactly one release per stream or its memory leaks for the
 * life of the process.
 *
 * Idempotent, and safe on a zeroed struct. Safe after the broken walk has
 * already run. */
void cloak_udp_piper_destroy(cloak_udp_piper_t *pp);

/* ---- accessors: diagnostics and the assertions that need them ---------- */

/* Peers currently held. Falls when a peer is retired. */
size_t cloak_udp_piper_peer_count(const cloak_udp_piper_t *pp);

/* Peers ever created, and peers retired specifically BY THE DEADLINE.
 * The second is what separates "the peer went away" from "we forgot it":
 * a test asserting only peer_count == 0 would pass against a piper that
 * never created the peer at all. */
size_t cloak_udp_piper_peers_created(const cloak_udp_piper_t *pp);
size_t cloak_udp_piper_peers_expired(const cloak_udp_piper_t *pp);

/* DATAGRAMS DROPPED BECAUSE A PEER'S OWN DATAGRAM QUEUE WAS FULL -- D5's
 * counter, and the only evidence this divergence leaves.
 *
 * Summed over every live peer's cloak_stream_t::recv_dropped_datagrams
 * plus every already-retired peer's final value, so it is a LIFETIME
 * total for the piper and does not fall when a peer retires. O(peers).
 *
 * A SILENT DROP WITH NO EVIDENCE IS WHAT MAKES PACKET LOSS
 * UN-DIAGNOSABLE, which is why it is here rather than only in the
 * stream: an operator seeing a UDP tunnel lose datagrams needs to know
 * whether the loss is in this process or on the path, and Go -- which
 * blocks instead of dropping -- has no equivalent number to compare
 * against. */
uint64_t cloak_udp_piper_dropped_datagrams(const cloak_udp_piper_t *pp);

/* Datagrams read from the local socket that were larger than one frame's
 * payload and were therefore refused whole rather than split or
 * truncated. This is D7's own counter: Go TRUNCATES these to 8192 and
 * sends the front of them (piper.go:25), so the number is also the count
 * of datagrams this port refused to corrupt. */
uint64_t cloak_udp_piper_oversize_datagrams(const cloak_udp_piper_t *pp);

/* Zero-length datagrams read from the local socket and swallowed, which
 * is what Go does too (its Write loop never runs, and no frame encoder on
 * either side will carry an empty payload). */
uint64_t cloak_udp_piper_empty_datagrams(const cloak_udp_piper_t *pp);

/* sendto(2) refusals -- events, not peers, so a peer refused ten times
 * counts ten. Non-zero is the only proof that the per-peer retry timer
 * has ever run, and therefore that D5's backlog state was actually
 * reached rather than merely coded for. */
uint64_t cloak_udp_piper_send_stalls(const cloak_udp_piper_t *pp);

/* Times read interest on the local socket was dropped because the
 * session's outbound pool could not hold one more worst-case frame. This
 * is the SESSION-WIDE pause, and it is exposed for the same reason
 * cloak_client_piper_retried_starts is: a test that only checked that the
 * bytes eventually crossed would pass just as well against a piper that
 * never applied backpressure at all and overran the pool. */
uint64_t cloak_udp_piper_pool_pauses(const cloak_udp_piper_t *pp);

/* Datagrams taken off the local socket over this piper's life, counted at
 * the recvfrom and therefore INCLUDING the ones that were dropped
 * afterwards -- oversized, empty, or from a source no peer could be made
 * for. Exposed because it is the only quantity from which the per-turn
 * read budget below can be observed at all.
 *
 * ---------------------------------------------------------------------
 * THE PER-TURN READ BUDGET, which this counter and the next exist to make
 * checkable. The read loop stops after CLOAK_UDP_PIPER_READ_BUDGET
 * datagrams in one entry, re-arms the socket and returns to the reactor.
 *
 * It is not an optimisation. Before it, the loop's only exits were EAGAIN
 * and the outbound pool -- and on a healthy link the pool never fills,
 * because every frame is accepted by a connection immediately, so one
 * peer with a full socket buffer held the whole reactor turn. The
 * datagrams this module DROPS rather than sends make that strictly worse:
 * they cost the pool nothing at all, so a flood of oversized or empty
 * ones is unbounded no matter how congested the session is. Everything
 * else this process owns -- the other peers' retry timers, the peer
 * deadlines, the pool's own readiness -- waits behind that loop.
 *
 * The budget is a COUNT OF DATAGRAMS and not of bytes, because the
 * pathological case is many tiny ones; and it is counted at the recvfrom
 * rather than at the write, so a dropped datagram spends budget exactly
 * as a forwarded one does. Pinned by test_udp_piper.c's
 * test_the_read_loop_yields_after_its_budget, which asserts the exact
 * count read in one reactor turn and that the remainder still arrives. */
uint64_t cloak_udp_piper_datagrams_read(const cloak_udp_piper_t *pp);

/* Times the read loop stopped because it had spent its per-turn budget,
 * as opposed to draining the socket (EAGAIN) or pausing on the pool.
 *
 * DISTINCT FROM cloak_udp_piper_pool_pauses, and the two must not be
 * folded together: a pool pause drops read interest and is resumed ONLY
 * by the session's on_writable, while a budget yield keeps interest and
 * is resumed by the re-arm the loop's own exit performs. A test that
 * could not tell them apart could not tell a working budget from one that
 * wedges the socket until the pool happens to drain. */
uint64_t cloak_udp_piper_read_yields(const cloak_udp_piper_t *pp);

/* Datagrams dropped because they came from an unknown peer and no peer
 * could be created for them -- the piper was at max_peers, had no
 * session, or could not open a stream. */
size_t cloak_udp_piper_refused_peers(const cloak_udp_piper_t *pp);

/* Streams the SERVER opened toward this client and this module refused; a
 * lifetime total over every session this piper has served. See
 * cloak_client_piper_rejected_streams for the full argument -- it is the
 * same one, and the ceiling is likewise per session, not per piper. */
size_t cloak_udp_piper_rejected_streams(const cloak_udp_piper_t *pp);

#endif
