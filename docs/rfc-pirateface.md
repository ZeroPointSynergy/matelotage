# RFC: a signed, off-site index for `pirateface_hub`

**Status:** draft, not posted anywhere. Written for the maintainer to read before any pull request exists.
**Author:** Captain Keanu (ZeroPointSynergy). Implementation: `matelotage` 0.1.0.
**Basis:** `pirateface_hub` 0.2.3, Windows, Python 3.12/3.13, CPU-only.

---

## 1. TL;DR

`pirateface_hub` is the only place that maps `org/model` to a magnet. When that API is unreachable,
every Pirate-Face-only model becomes undownloadable: there is no magnet to hand `libtorrent`, and the
Hugging Face HTTPS path has nothing to serve.

This proposes an **optional companion package** that publishes the same mapping as signed Nostr events
(kind `30078`) and patches three functions to consult them when the API fails. It is not a fork, not a
server change, and not enabled unless installed and configured.

- The record is an **attestation**, not a mirror: it carries the operator's own magnet, their
  infohash, and a SHA-256 manifest the signer computed and verified.
- It **joins the existing swarm**; it never founds a second one for a repo you already list.
- It **adds no server**, no key held by you, and no behaviour change for users who don't install it.
- Cost when inactive: **~6 ms** of import time. Cost when the API answers: zero network calls.

If the answer is "not upstream, keep it standalone", that works too — the patch surface is the same
three attributes either way, and it is already built that way.

---

## 2. The problem, stated precisely

Three distinct failures today:

1. **The site is down.** `api.lookup` returns `None` on a network error. `lookup_magnet` returns
   `None`, `_handle` has no magnet, and the download proceeds over Hugging Face HTTPS — fine for
   models that live there, a dead end for repos Pirate Face publishes and HF does not.
2. **The site is up but the CDN/origin is degraded.** Same `None`, same dead end, more confusing.
3. **The site is gone.** Every magnet, every torrent, and the licence curation vanish together,
   because they live in one database behind one domain.

Cases 1 and 2 are transient. Case 3 is the one worth engineering for: an index whose only copy is on
the machine being attacked is not a backup.

---

## 3. Proposal

A separate distribution, `matelotage` (CLI `mlt`), that:

- **publishes** signed records: `repo_id → magnet + sha256 manifest + licence`, on Nostr relays;
- **resolves** them when `pirateface.co` fails, verifying signature, author, repo binding, and the
  torrent's own hashes before a magnet is returned;
- **patches** exactly three functions in `pirateface.client.api` at import time, via a `.pth` file and
  a `meta_path` finder — the same mechanism `pirateface._boot` already uses for `huggingface_hub`.

Install is `pip install matelotage` plus `MATELOTAGE_NPUBS=<your npub>`; uninstall is `pip uninstall`.
Nothing changes for anyone who does neither.

---

## 4. The record

Kind `30078` (NIP-78 application data), parameterised by a `d` tag, so a repo has exactly one current
record per author.

```json
{
  "schema": 1,
  "repo_id": "HuggingFaceTB/SmolLM2-135M",
  "magnet": "magnet:?xt=urn:btih:413acf65…&tr=udp%3A%2F%2Ftracker.pirateface.co%3A6969",
  "hf": true,
  "license": "apache-2.0",
  "files": [{"path": "model.safetensors", "sha256": "…"}],
  "not_in_swarm": ["pytorch_model.bin", "flax_model.msgpack"],
  "seeders_at_publish": 3,
  "revision": "main",
  "timestamp": 1763150400,
  "revoked": false,
  "torrent_b64": "ZDg6YW5ub3VuY2U…"
}
```

Tags: `["d", "matelotage:v1:model:<repo_id>"]`, `["t", "matelotage"]`, `["l", "<licence>"]`.
The versioned `d` prefix is the one namespace decision I would want settled before anyone publishes at
scale — see §10.3.

Field notes that matter:

- **`hf`** mirrors your own semantics. `true` means "Hugging Face still has it", so the client keeps
  the 30-second swarm-then-HTTPS fallback. `false` means "Pirate Face only", which requires
  `torrent_b64` at validation time so `pf_only()` can serve metadata without you.
- **`files`** is the signer's own SHA-256, recomputed from bytes — not copied from the API, whose
  `sha256` field is a git blob id for non-LFS files and will not match.
- **`not_in_swarm`** exists because your torrents are honestly partial: one repo here ships 4 of 6
  files and streams the rest from HF on every download. A record that implied otherwise would be a
  boast. `mlt verify` reports the same split.
- **`seeders_at_publish`** is a dated measurement from `entry["seeders"]`, not a promise.
- **`torrent_b64`** is optional and capped: whole records are held to **32 000 bytes** on the wire.
  It is shed last, and only for `hf: true` records.

---

## 5. Trust model

- **Authors are pinned.** `MATELOTAGE_NPUBS` is an ordered allowlist. Resolution ranks by
  `(author_index, -created_at, event_id)`: within a key the newest wins (NIP-78 replacement), across
  keys an earlier key outranks a later one **including tombstones**. A community key can fill in
  models you haven't published; it can never overwrite your record or revive what you revoked.
- **A withdrawal is seen within one cache interval** (`MATELOTAGE_CACHE_TTL`, 300 s by default), not
  only at process start: records are re-resolved on that interval, and a failed refresh keeps serving
  the previous record rather than treating an unreachable relay as a revocation.
- **Everything is verified locally before use:** NIP-01 event id recomputed from canonical JSON,
  BIP-340 Schnorr signature checked with `coincurve`, `kind` asserted, `d` tag matched to the repo,
  author matched to the allowlist, `created_at` no more than 900 s in the future (old records are
  fine — being able to read a 2023 record is the point), and the torrent's v1 infohash
  matched to the magnet's `btih`.
- **Two modes, one switch.** `mirror` (default) serves only records signed by the operator's own keys
  — the first two allowlist entries, cold root and publisher.
  `keeper` serves any allowlisted author. Mirror exists so an integrator can be conservative without a
  code change.
- **Withdrawal is honoured, permanently.** A `revoked: true` record suppresses the repo for every
  reader, including readers running offline. Only a key of equal or higher precedence can restate.
- **The signature is the licence assertion.** No allowlist, no adjudication in code: the record says
  what its signer asserted, `mlt verify` prints it, and a takedown is respected because ignoring one
  would make the tool useless to the operator it exists to protect.

---

## 6. The patch surface

Three attributes and nothing else:

| function | behaviour added |
|---|---|
| `api.lookup_magnet(repo_id)` | on `None` (not `NOT_LISTED`), resolve a record and return its magnet |
| `api.torrent_file(repo_id, quant=None)` | same, returning `torrent_b64` bytes |
| `api.pf_only(repo_id)` | return the `hf: false` shape from a record when you are unreachable |
| `api.lookup` | **untouched, deliberately** — `pf submit` and `pf seed` must keep seeing your index, not ours |

Two properties I would ask you to check, because they are the parts that could bite you:

1. **A dict answer is authoritative.** If `lookup()` returns an entry at all — including one with no
   `magnet` key, which is your "accept the terms first" state — the patch does **not** substitute a
   relay magnet. It only falls back on `None` (network failure) or `NOT_LISTED`. This was a real bug
   found in review: an earlier version let a relay answer override your licence gate.
2. **`pf_only()` never hijacks a healthy site.** It returns `None` unless the site itself failed, so
   the 30-second swarm-then-HTTPS fallback keeps working exactly as it does now.

Each relay gets **1.5 s** and they are queried concurrently. A resolution runs two such queries —
revocation records first, then the model record — so a set of silent relays costs about **3 s**
before the Hugging Face path takes over; after two consecutive total misses the breaker stays open for
60 s and later lookups return instantly. That is the honest cost of asking a network that may not be
there.

Import cost when installed but unused: **~6 ms** (`meta_path` finder; nothing imported). An eager
`import pirateface.client.api` measured **+143 ms**, which is why it is lazy. `MATELOTAGE_DISABLE=1`
turns the whole thing off without uninstalling.

---

## 7. What it deliberately does not do

- **It does not seed.** A record is a pointer; preservation is seeders. It says so in the README and
  the numbers below are the reason.
- **It does not found parallel swarms.** For a repo you list, `mlt adopt` fetches *your* `.torrent`,
  refuses if its magnet and infohash disagree, and verifies the local bytes against **your piece
  hashes** before signing anything. Same infohash, same swarm, no duplicate listing — the thing you
  asked Andrii for in #30, from the other direction.
- **It does not touch `torrent.py`, `seed/*`, SHA-256 verification, or the HF cache**, and it does
  not reimplement your tracker policy: a record carries your magnet's trackers and strips your
  web seed, so a record never depends on the server it exists to survive.
- **It does not decide what may be shared.** See §5.

---

## 8. Evidence, measured rather than asserted

Read path, `PF_API` pointed at a closed port, cold cache, one record from one relay:

```
pf download HuggingFaceTB/SmolLM2-135M
  269.1 MB from the swarm, every fingerprint matched
  mlt verify → 9/9 files match the signed manifest
```

| web seed available | time |
|---|---|
| in the magnet | 24 s |
| only in the torrent's `url-list` | 28 s |
| none (magnet and torrent both stripped) | **4 m 18 s** |

Three seeders carried 269 MB in four minutes with no API and no web seed. **Zero seeders carry
nothing**, and a record should say so — hence `seeders_at_publish`.

Write path: `mlt adopt` on a live 269 MB repo takes **17.8 s** including the full piece check.

---

## 9. Review

Three adversarial rounds, fail-closed, by an independent agent with no stake in the code. The five
worth naming:

1. A relay magnet could override your licence gate (`lookup()` returning an entry with no magnet).
2. Unbounded relay frames: 400 × 200 KB events grew a resolver to 81 MB; now capped at 32 000 bytes
   per event and `2·limit+8` events.
3. Size was checked but **content was not**, so a corrupt local copy could be signed into a manifest
   the swarm could not reproduce. Now every piece is compared against the torrent's own hashes.
4. A Windows junction could make a torrent entry like `sub/id_rsa` hash a private file into a public
   record. Now every path is resolved and containment-checked before any byte is read.
5. `_server_entry` collapsed "not listed" and "unreachable", so a transient outage could found a new
   swarm and — being replaceable — overwrite a good record. Now only an explicit `NOT_LISTED`
   permits a new swarm, and never in `mirror` mode.

113 tests, ruff clean, and the published wheel installs into a clean virtualenv with the `.pth`
finders live. The only writes to a public relay have been test records from a throwaway key, all
deleted afterwards and confirmed gone by querying the relay.

---

## 10. Open questions for you

1. **Standalone or upstream?** My preference is standalone, with this RFC as the asking. Upstream would
   mean me sending three function bodies and a `.pth`; I'd rather you keep the core small.
2. **Whose key signs the operator records?** If this ever ships as a Pirate Face feature, the records
   should be signed by a key *you* hold — an offline root, a hot publisher, both in the allowlist.
   That is a policy decision, not a technical one, and the code supports it unchanged.
3. **Is `matelotage:v1:model:<repo>` the right `d` namespace?** If this ever becomes a Pirate Face
   feature, `pirateface:v1:model:<repo>` is the honest prefix and I would republish rather than
   squat on yours. Say which you want; it is cheap now and expensive later.
4. **`hf`, `torrent_b64`, and `pf_only`** are the three places where our reading of your contract
   could be wrong. If any of them misrepresents what your client expects, that is the part I most
   want corrected before this goes anywhere.
5. **Would you move one `if` in `transport.py`?** Right now the index is consulted proactively only
   for the `pirateface/*` namespace, and reactively only *after* Hugging Face answers 401/404. When
   Hugging Face itself is unreachable that call raises and the record is never read — even though it
   carries the magnet and the hashes. Since `pf_only()` returns `None` for any model Hugging Face can
   serve, the namespace gate is redundant, and swapping the two blocks would make your client survive
   an HF outage for keepers' records with no change in behaviour for anything else:

   ```python
   answered = self._answer(request, path)   # no namespace filter; None for ordinary models
   if answered:
       return answered
   response = self.inner.handle_request(request)
   ```

   I have implemented the equivalent locally as a transport wrapper (it only acts when the network
   call fails, and only ever answers `hf: false` records), so this is not a blocker — it is simply
   better in your repo than in mine.
6. **#30's reverse-hash endpoint.** If a batch hash lookup ever exists server-side, the record format
   above can carry it without a change; nothing here blocks that work.

---

## 11. What would make this worth doing at all

Not redundancy for its own sake. A modelless future for a repo that no longer has a host is a real
outcome — HF deletes models, mirrors disappear, takedowns happen. What survives that is a signed
statement, replicated where no single operator can delete it, carrying the hashes needed to prove the
copy is the copy.

That is all this is: an off-site copy of the index, with the operator still holding the pen.
