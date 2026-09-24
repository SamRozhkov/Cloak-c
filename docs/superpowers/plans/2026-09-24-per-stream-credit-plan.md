# Per-stream credit: the design that makes both halves work

**Status:** plan. Nothing below is implemented yet.

## Why

Two mechanisms are available without changing the wire, and each fails one
half of "faster and more stable". Measured, 16 MiB through the real
binaries and five full suite runs:

| design | 16 MiB ours↔ours | clean suite runs / 5 |
|---|---|---|
| read batching only | fails at 6,392,549 | 4 |
| stream pinning | completes, 167–233 MiB/s | 1 |

Spraying one stream's frames across connections needs an unbounded
reassembly window: TCP keeps order only within a connection, and the
receiver must hold everything that arrives ahead of the frame it is
waiting for. Measured: that window reached ~70 % of the transfer,
linearly, at every size and connection count, with the sender's queues
perfectly level (skew 0 bytes).

Pinning removes the reordering but introduces head-of-line blocking:
streams sharing a connection stop each other, because the only lever the
receiver has is stopping the whole connection. With 2 connections and 2
streams that is a coin flip, which is the rate `test_server_e2e` failed in
isolation — stalling at 65,537 bytes, one receive buffer, 4 runs of 5.

Credit removes the cause of both. The sender may not send more than the
receiver has advertised room for, so the receive buffer cannot overflow,
so nothing has to be dropped and no connection has to be stopped.

## The change

**A new frame type, carried in the existing `Closing` byte** — no header
change:

```
CLOAK_FRAME_CLOSING_NOTHING        0
CLOAK_FRAME_CLOSING_STREAM         1
CLOAK_FRAME_CLOSING_SESSION        2
CLOAK_FRAME_TYPE_WINDOW_UPDATE     3   (new)
```

Payload: 4 bytes, little-endian, the number of additional bytes the
receiver can now accept for that stream. Routed by the existing stream id,
so nothing in the dispatch path changes.

## Semantics

- **Initial credit** is `stream_recv_capacity`, known to both ends from
  the session config. Nothing is sent to establish it.
- **The sender** keeps `send_credit` per stream. `cloak_stream_write`
  emits at most `send_credit` bytes and returns the short count; the
  relay's existing read budget already knows how to pace on a short
  answer.
- **The receiver** accumulates freed bytes as the consumer reads, and
  emits one window update when the total reaches half the capacity. Half
  is the usual choice: it bounds the update rate at two per window while
  never letting the sender idle for want of credit.
- **A stream closing** needs no final update; the peer stops sending when
  it sees the closing frame.

## What it deletes

- The reassembly heap's byte budget and its refusal path: with credit the
  receiver cannot be given more than it can hold.
- Receive-side connection pausing (`rx_backpressure`), its per-connection
  counters and its resume timers.
- The per-batch read yield and its continuation timer.

Each of those is a pause, a timer or an allocation on the hot path, so
removing them is why this is expected to be faster as well as more stable.

## Order of work

1. Frame type and payload, with encode/decode tests.
2. Receiver: count freed bytes, emit updates at the half-capacity mark.
3. Sender: `send_credit`, bounded `cloak_stream_write`.
4. Relay: pace on credit as well as connection space.
5. Delete the backpressure and batching machinery.
6. Measure: 16 MiB both directions, five suite runs, and the bench matrix.

## What could go wrong, and what would show it

- **Deadlock if an update is lost or never sent.** A stream that has run
  out of credit and receives no update never sends again. The test that
  catches it is a transfer larger than one window — anything above 64 KiB
  — which is what `test_client_full_e2e`'s bulk case already is.
- **Update storms** if the threshold is too low. Visible as frame count
  far above payload/16132; worth asserting in the bulk case.
- **A stream whose consumer never reads** must stop its own sender and
  nothing else. That is the property pinning got wrong, so it deserves its
  own case: two streams, one consumer idle, the other must complete.


## Measured 2026-09-24: the branch without credit is not reliable, only lucky

A single repetition at 4, 8 and 16 MiB passed on the branch that has stages
1–3 but no enforcement — 145.8, 181.1 and 154.5 MiB/s, nothing failing —
and that nearly became "the bulk defect is already fixed".

It is not. Three further runs at 16 MiB with two repetitions each:

| run | result |
|---|---|
| 1 | both repetitions complete, 187.4 and 174.6 MiB/s |
| 2 | first completes at 189.3, second stalls at 4,224,869 |
| 3 | first stalls at 4,852,329, second never starts |

So the unbounded reassembly window is still there without credit; it simply
does not always overflow. One trial was an anecdote, again.

That settles the open question this plan exists for: credit is not an
optimisation on top of a working stack, it is what makes the stack work at
all above a few megabytes. Stage 4 has to land.
