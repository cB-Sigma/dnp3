# Changelog

## Unreleased

Fixed:

- GET_FILE_INFO (g70v7) answers with the file name of the request again,
  as in v0.3.0. IEEE 1815-2012 4.4.18 has the file name octets "filled in
  with the same data as in the request"; the base name v0.3.1 gave
  (#8) did not follow it. Directory entries keep the base name (5.3.6).

## v0.3.1 (2026-11-07)

Fixed, all reported with fixes by @boeboe (issues #2 to #5, PRs #6 to #9):

- `PointDB.Freeze` with clear set counters to 0 directly: no counter
  (g22) event was buffered and the deadband went on comparing with the
  value before the clear. The clear now goes through the same change
  detection as `Update`, under the lock: an event when the counter was
  not 0 already, none otherwise.
- The outstation treated any request with the sequence number and octets
  of the previous one as a retry and repeated the cached response, a
  READ included, and across connections. A repeated READ is now answered
  with the current values, and a request on a new connection is never
  the retry of one on the old.
- GET_FILE_INFO (g70v7) answered with the full path as the file name
  where the directory listing gives the base name. It now answers with
  the base name of the normalised path; the root keeps the name it was
  asked by.
- `Master.keepAlive` waited the full `Timeout` after each
  REQUEST_LINK_STATUS before restarting the `KeepAlive` timer, so idle
  keep-alives came every `KeepAlive` + `Timeout`. The interval now
  restarts when the answer frame arrives (13.2.3.3); an unanswered
  request still ends the connection at `Timeout`.

## v0.3.0 (2026-10-12)

Added, all backwards compatible:

- Package `gateway`: a data concentrator. Points a master reads from
  downstream outstations (`Source`, fed by `Source.Data` from
  `SessionConfig.OnData` and `MasterConfig.OnUnsolicited`) are
  republished at other indexes in the gateway outstation's `PointDB`;
  events below become events above with their own time, even when the
  value is unchanged; mapped CROBs and analog outputs received by the
  gateway's outstation go down (SELECT as SELECT, OPERATE as a fresh
  select-and-operate pair so no poll comes between them, DIRECT_OPERATE)
  and the source's status comes back; `Source.SetOnline(false)` marks
  the source's points COMM_LOST without ONLINE.
- Package `profile`: the device profile document in XML from a `PointDB`
  and device settings (`New`, `Write`), read back (`Read`) and turned
  into a `PointDB` (`Document.Define`), with names, scaling, units and
  state names per point.
- Package `authority`: a reference update key authority (methods 3 to 5
  and 67 to 69) as a service, with a user register, per-master tokens
  and outstation lists, the status change sequence number kept per
  outstation, g120v8 certificates issued for registered users, and an
  audit log; `authority.Client` is the master's `dnp3.Authority` backed
  by it. The master–authority protocol (JSON over HTTP) is our own; the
  standard leaves it open.
- Point database: `UpdateWith` with event modes (`EventDetect`,
  `EventForce`, `EventSuppress`, `EventOnly`) and `UpdateFlags`
  (flags-only changes, value kept).
- Event buffers: `SetTypeCapacity` (a bound per point type besides the
  per-class one) and `SetDropOldest` (a full buffer loses its oldest
  event instead of the new one; the overflow is reported either way).
- Interop tests against opendnp3 3.1.2 for the new roles: opendnp3's
  outstation below the gateway and opendnp3's master above it; opendnp3's
  master reading forced and flags-only events of our outstation.

## v0.2.0 (2026-10-11)

Interop tests extended to TLS, UDP and serial lines, every object type
opendnp3 3.1.2 serves, freezes, restarts, the link layer, lost
confirmations, and Secure Authentication v5 against opendnp3 2.1.0-RC5
(see README.md, "Interop tested against"). The API only grew.

Added:

- `Master.RunSession` and `SessionConfig`: start-up sequence, periodic
  integrity polls and class scans, polls on IIN1.1 to 1.3, an integrity
  poll after an event buffer overflow, time synchronisation when asked,
  start-up again after a restart. `Master.SyncTime` runs the LAN or
  non-LAN procedure on its own.
- Time-and-interval points (g50v4): `PointDB.SetTimeAndInterval`,
  `PointDB.TimeAndInterval`, served in class 0 and to reads, written by
  the master (`TimeAndIntervalHandler`).
- Virtual terminal ports (g112, g113): `PointDB.VirtualTerminalOutput`,
  `VirtualTerminalHandler`.
- Deadbands on counters and frozen counters (`DBPoint.Deadband`).
- `OutstationConfig.UnsolOffline`.

Fixed:

- With `LinkConfirm`, the master's read loop waited for the sender to
  answer a frame (an unsolicited response to confirm, a link status
  request) while the sender held the link waiting for the acknowledgement
  the read loop had not read: every confirmed request timed out against
  opendnp3. Answers from the read loop now go out in order from their own
  goroutine.
- An outstation unsolicited series that ended unconfirmed (no retries
  left) left its events buffered until another event arrived; a new
  series now carries them after `UnsolOffline`.
- A time never set (or before 1970) was encoded as a wrapped 48-bit
  value; it is now 0.
- Closing a serial port while it was being read was a data race in
  goburrow/serial (found by `go test -race` on a pty); the port opened by
  `OpenSerial` now waits for the read in progress.
- A master in aggressive mode facing an outstation that refuses g120v3
  as an unknown or malformed object (opendnp3's experimental SAv5) failed
  every critical request; it now stops using aggressive mode with that
  outstation and sends the request again with a challenge.

## v0.1.0 (2026-10-11)

First release.
