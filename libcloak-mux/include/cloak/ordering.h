#ifndef CLOAK_ORDERING_H
#define CLOAK_ORDERING_H

/* WHETHER A SESSION'S STREAMS ARE AN ORDERED BYTE STREAM OR A SEQUENCE OF
 * DATAGRAMS -- Go's SessionConfig.Unordered
 * (/Users/sam/Cloak/internal/multiplex/session.go), which this port has
 * carried on the wire since module 3 (the auth record's flag byte, bit 0)
 * without anything below the handshake ever acting on it.
 *
 * THIS HEADER EXISTS ONLY BECAUSE OF AN INCLUDE DIRECTION. The mode is a
 * property of a SESSION -- one session is ordered or unordered as a whole,
 * and its streams inherit that; there is no such thing as one unordered
 * stream on an ordered session. But cloak/session.h includes
 * cloak/stream.h and not the other way round, and cloak_stream_init has to
 * take the mode (see below), so the type cannot live in session.h. It
 * keeps the cloak_session_ prefix because the session is what owns it; it
 * lives here because that is the only place both layers can see it. This
 * is the one difference from cloak_conn_framing_t, which cloak/conn.h can
 * declare in place precisely because conn is the layer that owns it.
 *
 * WHAT THE TWO MODES ACTUALLY MEAN, since nothing in this module's task 2
 * implements the difference yet and a name alone is not a specification.
 * In Go, makeStream (internal/multiplex/stream.go:48-66) picks the
 * receive buffer from this one bit:
 *
 *   ORDERED    a streamBuffer: frames are reassembled by sequence number
 *              into a gap-free byte stream, out-of-order arrivals wait in
 *              a priority queue, and Stream.Write is free to split one
 *              write across several frames because the far end will put
 *              them back together. This port's cloak_stream_t implements
 *              exactly this today (its seq min-heap), which is why ORDERED
 *              is the mode every existing call site is being given.
 *   UNORDERED  a datagramBufferedPipe: there is no reassembly and no
 *              reordering at all -- one frame in is one datagram out, and
 *              a frame that arrives late is simply late, not buffered
 *              until its predecessors show up. Go correspondingly refuses
 *              to split a write that does not fit in one frame
 *              (io.ErrShortBuffer -- stream.go:132-135) rather than
 *              silently fragmenting a datagram, and stops pinning a
 *              stream to one underlying connection (Stream.assignedConn
 *              is documented as "not used in unordered connection mode"
 *              at stream.go:38-43).
 *
 * ZERO IS DELIBERATELY INVALID, AND THE MODE IS A FIELD OF
 * cloak_session_config_t RATHER THAN A PARAMETER FOR THAT REASON. This is
 * the same mechanism as cloak_conn_framing_t and it is here for the same
 * measured reason, restated because it is the whole point of the field: a
 * mode passed only as an argument has no zero value unless a caller types
 * one, so it protects nothing, whereas a mode that is a field has one on
 * every memset -- and memset + assignments is how every config struct in
 * this tree is built. A zeroed or partially-filled cloak_session_config_t
 * therefore FAILS cloak_session_init with
 * CLOAK_SESSION_ERR_INVALID_ORDERING instead of quietly getting whichever
 * mode happened to be numbered 0.
 *
 * AND THE WRONG CHOICE IS INVISIBLE TO EVERY C-TO-C TEST IN THIS TREE,
 * WHICH IS WHY THE MECHANICAL DEFENCE IS THE ONLY DEFENCE. Both ends of
 * every test in the first eight modules are ours. A session pair that is
 * ordered at both ends and a session pair that is unordered at both ends
 * both pass every round-trip assertion; what fails is a C end talking to a
 * peer that made the other choice -- a real ck-client, or the same C code
 * after a later task teaches one end to honour the handshake flag. Nothing
 * in a self-consistent round trip can see a call site that forgot to set
 * the mode, so the construction failure is what sees it instead. That is
 * the exact shape of the defect this port shipped for five modules with
 * conn framing; see the 46-line comment at the top of cloak/conn.h.
 *
 * MEASURED, not asserted, against the 69-test suite: deleting the check
 * from cloak_session_init -- leaving the enum, the field and every call
 * site in place -- fails test_session and nothing else; deleting it from
 * cloak_stream_init fails test_stream and nothing else; writing it as
 * `ordering == CLOAK_SESSION_ORDERING_INVALID`, so that 3 and 255 are
 * accepted while 0 is still rejected, fails test_session; moving the
 * check after the other field checks fails test_session at ONE assertion
 * (its zeroed-config case, the only thing in the tree that pins the
 * order); and replacing either end's derivation of the mode from the
 * handshake's unordered flag with a fixed ORDERED fails
 * test_client_connector (both ends) and test_dispatcher_auth (the
 * server's). Numbers from this module's task 2 and its fix round; the
 * per-assertion table lives beside the cases themselves, in
 * test_session.c's own case 1 -- read it before deleting either half of
 * that case, because this branch's first attempt at that table had the
 * two halves the wrong way round. */
typedef enum {
    CLOAK_SESSION_ORDERING_INVALID   = 0, /* deliberate: an un-updated call site FAILS construction */
    /* Go's Unordered == false: reassembled byte stream
     * (internal/multiplex/stream.go:59-63 picks NewStreamBuffer). */
    CLOAK_SESSION_ORDERING_ORDERED   = 1,
    CLOAK_SESSION_ORDERING_UNORDERED = 2  /* Go's Unordered == true: datagrams, no reassembly */
} cloak_session_ordering_t;

/* The return value of cloak_session_init and cloak_stream_init when the
 * ordering mode is CLOAK_SESSION_ORDERING_INVALID or outside the enum.
 * Distinct from the -1 that reports every other construction failure for
 * the same reason CLOAK_CONN_ERR_INVALID_FRAMING is: a test that accepted
 * any non-zero return would pass unchanged against an implementation that
 * never looked at the field at all, which is precisely the implementation
 * this whole mechanism exists to rule out. Checked BEFORE every other
 * field, so the error a caller gets names the thing they actually forgot
 * rather than whichever other field their memset also left at zero. */
#define CLOAK_SESSION_ERR_INVALID_ORDERING (-2)

#endif
