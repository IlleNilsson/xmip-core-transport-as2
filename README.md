# xmip-core-transport-as2

AS2 transport: EDI over HTTP, RFC 4130 — one message is one Stream, its Party ids beside it, answered with a signed MDN; a Receive Location answers Parties, a Send Location posts to one. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

Requests go on connections kept between them (`http::endpoint::Connections`, offering HTTP/1.1): the transport holds them and hands them to every client it makes, so a call costs one exchange and not a connect, a TLS handshake and a `Connection: close`, as it did until 2026-09-27.

A Receive Location keeps its listener, bound on the first receive, and the connections senders keep open on it (`http::inbound::Inbound`): each receive takes the next request from whichever sends first, where until 2026-09-27 each receive bound a listener of its own, answered one request with `Connection: close`, and refused a request that came between two receives. The peer an origin names comes from `http::server` (`serve_one_from`, and the `Inbound`), where AS2 accepted and read its own connection until then.

The Party's endpoint is kept as written and read by `net::Endpoint` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net) under the schemes this technology declares — `as2://` is `http://`, `as2s://` is `https://`. Until 2026-09-28 an `as_http` function rewrote the URL before it was read.

## Acknowledged after the receive cycle

A Party waits on its connection for its MDN until the runtime's whole receive cycle has ended (runtime-model section 5). The cycle ends in one of three verdicts (`receipt::Receipt::answer`):

- **Accepted**: the MDN — signed where a signer is set, carrying the MIC computed as the message was read.
- **Refused**: an error MDN, signed the same way, its disposition `processed/error:` with the RFC 4130 section 7.4.3 modifier that says why — `authentication-failed` for a sender not identified, `unexpected-processing-error` for one not permitted or content refused. It is a final answer the Party files and does not send again. A Party that asked for no MDN hears HTTP's `401`, `403` or `422` (`http::server::refused`).
- **Failed**: `503 Service Unavailable`, never an error MDN: the transient failure AS2 senders retry, so the Party keeps the message and resends it.

A POST that is not this Party's AS2 message is answered `400` (or `503`) at once. No round trip is added: the MDN goes back on the same exchange, only later.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
