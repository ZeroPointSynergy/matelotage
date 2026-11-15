# matelotage

> **What one keeps, the other keeps.**

**Unofficial.** This is a separate project. It is not affiliated with, endorsed by, or maintained by
Pirate Face, and it holds no authority over their index — it reads their catalogue and signs
statements about it. Bugs in `pirateface_hub` belong in
[their tracker](https://github.com/pirateface/pirateface_hub/issues), not here.

A *matelotage* was a written agreement between two buccaneers: shared property, mutual protection,
and mutual inheritance. The part that matters here is the contract — two keepers, 
each bound to preserve the other's share.

Matelotage is a preservation layer for open models. It keeps a signed, replicated index of
`repo → magnet + sha256 manifest` on Nostr relays, and patches [Pirate Face](https://pirateface.co)
so a download still resolves when the site is unreachable. The model survives the loss of its host,
its site, or its repo, as long as someone still seeds it.

```
pip install matelotage        # brings pirateface with it
mlt doctor                    # is the bridge live? who do I trust? which relays answer?
```

## The problem

A model on the internet has three points of failure: the host (Hugging Face), the index that says
where it is (Pirate Face), and the machine that happens to have the bytes. When the middle one goes
away, the swarm is still there — nothing can find it.

## Three layers

| Layer | Command | What survives |
|---|---|---|
| **Index** | `mlt publish` | the record outlives the site |
| **Bind** | (automatic) | the download outlives the site |
| **Attest** | `mlt adopt`, `mlt verify` | the content outlives the site |

`mlt adopt` is the one that does real work. When Pirate Face already lists the repo it fetches **their**
`.torrent`, checks that its magnet and infohash agree, verifies every file in it exists locally at the
right size, and signs a record carrying **their** magnet — one repo, one swarm, the record joins the
crowd that is already there instead of founding a parallel one. It attests the files with its own
SHA-256 manifest, independently of what the server claims.

Only for repos nobody has published does it build a fresh torrent, and then it says so, because a new
torrent is a new swarm with nobody in it.

## Two modes, one switch

```
MATELOTAGE_MODE=mirror    # default
MATELOTAGE_MODE=keeper
```

**`mirror`** serves records signed by the operator's own keys — the first two entries in
`MATELOTAGE_NPUBS`, the cold root and the publisher — and only for repos Pirate Face still publishes.
A fresh install can therefore never serve something the site didn't, and a fill-in keeper at index 2+
can never redirect a repo the operator already signed. This is the mode a maintainer can adopt
without taking a position on anything.

**`keeper`** serves any record signed by a key you trust — including models Pirate Face never
listed. You choose whose word you take by choosing whose npub is in `MATELOTAGE_NPUBS`.

Neither mode changes what you may download. The switch governs what matelotage puts on a swarm
under someone's signature.

## Keys

```
mlt keygen        # nsec (signing), npub (identity)
```

Put npubs in `MATELOTAGE_NPUBS`, comma-separated. **Position is authority**: index 0 outranks
everything after it.

- index 0 — the cold root. Kept offline, publishes nothing but key revocations.
- index 1 — the publisher. Signs records day to day.
- index 2+ — other keepers. They can fill gaps, never correct or revive what index 0 has said.

A repo tombstone (`mlt revoke`) withdraws a model, and a lower-precedence key cannot undo it. A key
revocation record lets the cold root kill a stolen publisher key across every client without a
release.

Two consequences of "position is authority", stated plainly because they surprise people:

- **A repo the cold root signed can only be withdrawn by the cold root.** The publisher's tombstone
  loses to a live record at index 0. That is the price of the cold root being able to override a
  compromised publisher, and it is why index 0 is kept offline and used rarely.
- **A withdrawal reaches a running downloader within `MATELOTAGE_CACHE_TTL`** (default 300 s), not
  instantly and not only at restart. Records are re-checked on that interval; a failed refresh keeps
  serving the old record, because an unreachable relay is not a withdrawal.

## What it does not do

- **It does not decide what may be shared.** There is no licence allowlist in the code. A record
  carries the licence its signer asserted, and the signature is the claim. Withdrawal is honoured;
  judgement is not ours.
- **It does not seed.** `adopt` builds or adopts a torrent and signs a record; somebody still has to
  keep the bytes. Preservation is seeders, not signatures. Measured on 2026-11-14: the same 269 MB
  model took **24 s** when the operator's web seed was available and **4 m 18 s** from three peers
  alone. With zero peers it would never arrive, no matter what the record says.
- **It records what it does not keep.** Pirate Face's swarms are partial — one small repo here ships
  4 files of 6 in the torrent and streams the rest from Hugging Face every time. A record therefore
  carries `not_in_swarm`, naming the files the swarm cannot serve, and `seeders_at_publish`, the
  health of the swarm at signing time. A dated measurement is not a promise.
- **It does not touch `pirateface_hub`.** Not a fork, not a patch file — a `.pth` that swaps three
  module attributes at import time (`lookup_magnet`, `torrent_file`, `pf_only`). `api.lookup` is
  deliberately left alone so `pf submit` and `pf seed` behave exactly as before.
- **It does not speak while the site is answering.** If `pirateface.co` replies, its answer stands,
  including the licence gate. The fallback only speaks into silence.
- **When Hugging Face is unreachable, it answers anyway.** Upstream consults the index only after
  Hugging Face answers 401/404, so an HF outage would otherwise raise before any record is read. A
  fourth, deliberately narrow patch sits outside that transport: if the network call *fails*, it tries
  the index before re-raising. It can only ever answer `hf: false` records — `pf_only()` returns
  `None` for everything Hugging Face can serve — so an ordinary model is never answered from a record
  by mistake. It wraps the synchronous client only — huggingface_hub's async factory is left alone —
  and it only treats genuine network failures as "the hub is gone"; anything else propagates unchanged.
  Proven end-to-end with both services pointed at a closed port (see below). Set
  `MATELOTAGE_OFFLINE_FIRST=0` to switch it off.
- **It refuses hardlinked files by default.** A hardlink resolves to itself, so the containment check
  cannot see where it came from, and it is the one link a normal Windows user can make without admin
  rights. `MATELOTAGE_ALLOW_HARDLINKS=1` accepts them when you really do keep the bytes that way.

## Where the records live

Nobody hosts records for you. `mlt adopt` publishes them to relays; a relay is a server that accepts
kind-30078 events and serves them to anyone who asks. Three consequences:

- **Someone must publish the first copy**, and that is the operator: the key in `MATELOTAGE_NPUBS`
  signs, and the record only exists once a relay accepts it. Nothing is stored in this package.
- **Relay policies differ.** Measured 2026-11-14, of twelve public relays tried: **two** accepted a
  kind-30078 write and served it back (`relay.primal.net`, `relay.snort.social`); damus was down, nos.lol
  accepted the socket and never answered, three wanted payment, one refused the kind outright, and the
  rest were unreachable or timed out. Deletion of a test record was honoured (`events_after=0`).
- **Two relays is thin.** For anything you mean to preserve, run your own relay (strfry or
  nostr-rs-relay will store these events) or add several you trust with `MATELOTAGE_RELAYS`. A record
  is only as durable as the number of independent servers holding it.

A resolution queries the list concurrently and takes the newest verified answer, so adding relays
costs no latency; dead ones cost only the timeout.

## Constants worth knowing

- Relay event budget: **32 000 bytes**, measured against the default relays; a record that would
  not fit drops its inline torrent rather than its file manifest.
- Relay timeout: **1.5 s** per relay, queried concurrently. A resolution runs two queries, so a
  set of dead relays costs about **3 s** before the standard Hugging Face path takes over; two total
  misses in a row open a 60 s breaker and later lookups return instantly.
- Circuit breaker: two lookups where no relay answered → 60 s of silence.
- Manifest hashes are real SHA-256 of the bytes. (Pirate Face's API mixes git blob ids and LFS
  hashes; we recompute, we do not copy.)

## Measured, not asserted

With **both** services unreachable — `PF_API` and `HF_ENDPOINT` pointed at a closed port — the real
client still resolved from a signed record and pulled the bytes from the swarm:

```
🏴‍☠️ pirateface  acme/offline-model is on Pirate Face (2 files, 0.2 MB), downloading from the swarm
SNAPSHOT OK
  config.json        exists=True sha256_matches=True
  model.safetensors  exists=True sha256_matches=True
```


On 2026-11-14, with the site's API pointed at a closed port and no web seed anywhere:

```
record resolved from one relay   →  magnet 413acf65… (Pirate Face's own)
pf download HuggingFaceTB/SmolLM2-135M, cold cache
  269.1 MB from the swarm, every fingerprint matched
  mlt verify  →  9/9 files match the signed manifest
```

Three runs, same model, same dead API:

| web seed | time |
|---|---|
| in the magnet | 24 s |
| only in the torrent's `url-list` | 28 s |
| **stripped from both** | **4 m 18 s** |

That last row is the one that counts: records carry no web seed, so a record never depends on the
server it exists to survive. `storage_blob()` drops `piece layers` and `url-list` — both sit outside
the info dict, so the infohash is untouched and the record still joins the same swarm.

## Related

- [pirateface_hub](https://github.com/pirateface/pirateface_hub) — the downloader this works
  alongside. Not a fork, not a dependency of theirs; it installs beside the package and patches three
  function attributes at import time (see `mlt doctor`, and `MATELOTAGE_DISABLE=1` to turn that off).
- [docs/rfc-pirateface.md](docs/rfc-pirateface.md) — a written ask, kept as a document rather than a
  feature request: what it would take for the maintainers to own this, if they ever want to.

The project is standalone by design: it adds a layer beside Pirate Face rather than inside it, and it
asks nothing of the maintainers. If they ever want to own the idea, the integration is small enough
that this repository can be retired without stranding anyone.

## Status

Pre-release, developed against `pirateface` 0.2.3 on Windows. The read path and the write path both
run offline against loopback relays; the tests are the contract. `restate` is a stub that refuses
politely rather than pretending.

## Licence

MIT.
