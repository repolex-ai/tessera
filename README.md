# tessera

tessera checks who is asking a Subtexture daemon, and whether they may read or write its named graphs.

A *tessera* was the small clay, bone or lead admission token handed to a guest or citizen in antiquity and checked at the gate of the theatre. In the Subtexture stack, `git-lex` is the ticket booth that binds Ed25519 keys and signs tokens and service grants; Syrinx, Pan, git-lex, ravel and Horae each check those tokens at their own turnstile through this library.

| Module | Job | Reads disk? |
|---|---|---|
| `verify` | Check an `Authorization: Bearer <token>` header against a key set and, for a service acting under a grant, a grant list | No |
| `access` | Check whether a caller may read a named graph from its `owner`, `visibility`, and `readableBy` metadata plus the machine's `Owner` | No |
| `keyring` | Load and refresh `~/.lex/identity/{jwks.json, grants.json, owner.json}`, or stand down (`Keyring::Off`) for standalone installs | `std::fs` only |

tessera opens no sockets, pulls in no HTTP framework and uses no async runtime. It depends on `ed25519-dalek`, `base64`, `serde` and `serde_json` alone — the exact versions already in Syrinx, Pan and git-lex.

## Using it

```toml
[dependencies]
tessera = { git = "https://github.com/repolex-ai/tessera" }
```

```rust
use tessera::{
    check_read, require_scope, www_authenticate_invalid_token, GraphAccess, Keyring, Visibility,
};

// Once at startup (`Keyring::Off` when running standalone with no identity block):
let keyring = Keyring::subtexture_in_home(&home_dir);

// On each HTTP request:
//   - Ok(None)         -> no Authorization header (anonymous caller)
//   - Ok(Some(caller)) -> verified Ed25519 identity or granted service
//   - Err(why)         -> 401 Unauthorized + WWW-Authenticate: www_authenticate_invalid_token(&why.0)
let caller = keyring.identify(authorization_header, now_secs)?;

// Optional scope check on routes where a service grant must name a capability:
if let Some(ref c) = caller {
    require_scope(c, "pan:read")?; // Err(Denial) carries http_status() == 403 + WWW-Authenticate
}

// Per named graph (from its description in the store's unnamed metadata graph):
let policy = GraphAccess {
    owner: Some("https://repolex.ai/7r1pl3f0rc3/tr1pl3x/soul/Soul/tr1pl3x"),
    visibility: Visibility::parse(Some("shared"))?,
    readable_by: &["https://repolex.ai/7r1pl3f0rc3"],
};
let machine_owner = keyring.owner()?;
check_read(caller.as_ref(), &policy, machine_owner.as_ref())?;
```

## What `verify` checks

### Plain identity tokens (`git-lex`, 2026-11-15)

1. `alg` is `"EdDSA"`, fixed in code and never chosen by the token's header; `typ` is not `"grant+jwt"`.
2. `kid` selects which Ed25519 entry in `jwks.json` to try, and nothing more.
3. The signature passes strict Ed25519 verification (`VerifyingKey::verify_strict`) against that listed key.
4. `sub` equals the exact address `jwks.json` records for that key (`https://repolex.ai/{squad}/{user}/soul/Soul/{user}`, or `https://repolex.ai/soul/Soul/{id}` on older entries).
5. `iat <= now + 60`, `exp > now`, and `exp - iat <= 86400` (at most 24 hours).
6. `aud == "subtexture"`.

### Service tokens carrying a grant (`git-lex`, 2026-11-17)

When a UI server or worker acts for someone, it holds its own Ed25519 key and presents a short-lived JWT carrying a `grant+jwt` signed by the grantor:

1. The inner grant is verified strictly with the grantor's listed key (`typ == "grant+jwt"`, `sub` and `iss` match the grantor's listed address, lifetime 2 to 366 days, `aud == "subtexture"`, Ed25519 `cnf.jwk`).
2. The grant's `jti` is on `~/.lex/identity/grants.json` with no `ended` timestamp, matching `grantor`, `service` and `x` (`grants.json` is read on every check so `git lex identity revoke` takes effect immediately).
3. The outer token's signature verifies strictly with `cnf.jwk.x`.
4. `outer.sub == grant.sub`, `outer.act.sub == service`, and `outer.iss == "service:{service}"`.
5. The outer token passes the 24-hour window and does not outlive `grant.exp`.
6. `outer.aud == "subtexture"`.

Both paths return a [`Caller`] carrying `subject` (the verified Soul IRI), `genesis` (the 40-hex `kid`), `username`, `squad`, `actor`, `scope`, and `expires`.

## What `access` checks

Each named graph describes itself in its store's unnamed metadata graph (`subtexture 0.6.0`, `2026_11_19_NAMED_GRAPH_DESCRIPTIONS_SPEC.md` Section 12):

- `Visibility::Public` (`"public"`): anyone may read, including `caller == None`.
- `Visibility::Private` (`"private"`, the default when `subtexture:visibility` is omitted): only the graph's `subtexture:owner` and the machine's `Owner` (`owner.json`) may read.
- `Visibility::Shared` (`"shared"`): readable by `owner`, the machine's `Owner`, any Soul IRI listed in `subtexture:readableBy`, and any caller whose squad IRI (`https://repolex.ai/{squad}`) is listed in `subtexture:readableBy`.

Refusals return [`Denial::Unauthenticated`] (`401` when `caller` is `None`) or [`Denial::Forbidden`] / [`Denial::InsufficientScope`] (`403` when `caller` is known), along with RFC 6750 `WWW-Authenticate` header values.

## Tests

```sh
cargo test
```

## Looked after by

tr1pl3x, beside the Subtexture ontologies and specs. Token and grant contracts are w4r3z's (`git-lex`), with verification cases from m4xx (`syrinx`) and w4r3z-pan (`pan`).
