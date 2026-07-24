# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```
crystal spec                       # run all specs (interop specs auto-skip without Ruby/ActiveSupport)
crystal spec spec/session_spec.cr  # run one spec file
crystal spec spec/session_spec.cr:42  # run the spec at a given line
crystal tool format                # format (enforced; .editorconfig defines style)
shards install                     # install dependencies
```

There is no separate build step — this is a library shard, consumed via `require "kemal-cookie-session"`.

## What this is

A **client-side (cookie-store) session for Kemal**: the entire session lives inside one AES-256-GCM encrypted, authenticated cookie. Nothing is stored server-side (no engine, no session registry, no GC). Two hard constraints shape everything:

1. **Rails 8 byte-compatibility.** The cookie is produced/consumed exactly as Rails' `ActionDispatch::Session::CookieStore` does by default, so a Kemal and a Rails app sharing `secret_key_base` + cookie name read/write each other's sessions. Any change touching crypto, the metadata envelope, or the wire format must preserve this — it is the project's whole reason to exist.
2. **`kemal-session` API compatibility.** The public API mirrors the `kemal-session` shard, and both define `Kemal::Session` / `env.session` — so the two **cannot** be used together.

## Architecture

The code is a strict bottom-up crypto stack; each layer only knows about the one below it. `src/kemal-cookie-session.cr` is the entry point (named for the shard, as Crystal requires) and `require`s the files below — which live in `src/kemal/`, mirroring the `Kemal` module they reopen — in dependency order:

- **`lib_crypto.cr`** — raw `LibCrypto` EVP bindings. These exist because Crystal's stdlib OpenSSL does **not** expose the GCM auth-tag get/set control ops (`EVP_CTRL_GCM_GET_TAG` / `SET_TAG`), which Rails-compatible AES-256-GCM requires.
- **`crypto.cr`** (`Kemal::Session::Crypto`) — primitives matching Rails' defaults: `derive_key` (PBKDF2-HMAC-**SHA1**, 1000 iterations, 32-byte key) and `encrypt`/`decrypt` (AES-256-GCM, 12-byte IV, 16-byte tag, **no AAD**). Raises `Crypto::Error` on auth failure.
- **`message_encryptor.cr`** (`MessageEncryptor`) — reimplements the subset of `ActiveSupport::MessageEncryptor` the cookie jar uses. Owns the two Rails-specific formats: the **wire format** `strict_base64(ciphertext)--strict_base64(iv)--strict_base64(tag)` and the **legacy metadata envelope** `{"_rails":{"message":<b64(payload)>,"exp":<iso8601|null>,"pur":"cookie.<key>"}}`. Verifies purpose + expiry on decrypt. Works with *raw* (unescaped) cookie strings.
- **`config.cr`** (`Config`) — the `Kemal::Session.config` singleton (`INSTANCE`). Caches a `MessageEncryptor` keyed by `{secret, salt, iterations}` and rebuilds it when any of those change. `purpose` is always `"cookie.#{cookie_name}"`. `secret` is aliased as `secret_key_base`.
- **`session.cr`** (`Session`) — the store: a **flat** `Hash(String, JSON::Any)` (Rails-shaped, so a key lives in one namespace regardless of type). Handles cookie read (decrypt on init) / write (`save` encrypts and assigns the cookie; `commit` does that once if the store is dirty). URL/CGI escaping of the wire value happens here, *not* in `MessageEncryptor`. Mutations only call `touch` (mark dirty) — they do **not** encrypt.
- **`handler.cr`** (`Session::Handler`) — the required `HTTP::Handler` that commits the session once per request. Because `Set-Cookie` is a header and Crystal silently ignores cookies added after the first unbuffered write (8 KB output buffer), it wraps `response.output` in a `CommitGuard` that commits just before the first body byte, and commits again as it unwinds for bodyless responses. `touch` raises `HandlerRequired` when the handler isn't in the chain (`context.session_deferred?`) and `ResponseAlreadySent` once the body has started (`context.session_sent?` — on the *context*, since a session can be built after the response starts). Consequence: `CookieOverflow` surfaces from the commit, not from the setter.
- **`flash.cr`** (`Session::Flash`) — minimal read-once flash on top of the session store (not Rails' FlashHash).
- **`csrf.cr`** (`Session::CSRF`) — a port of `ActionController::RequestForgeryProtection` (+ its `SessionStore` strategy) on top of the session: the real token at `session["_csrf_token"]` (unpadded urlsafe base64 of 32 bytes), masked tokens (`pad + (pad XOR HMAC-SHA256(real, identifier))`), the global (`"!real_csrf_token"`) vs per-form (`"<action_path>#<method>"`) identifiers, the `Origin` check, and a `Handler`. The `Handler` is the intended entry point (protect everything, exempt deliberately via `except:`/`skip`, like Rails' default-on `protect_from_forgery`); it raises `InvalidAuthenticityToken` and leaves the response to a Kemal `error` handler, so apps must register one or Kemal renders a 500 instead of Rails' 422. `env.verify_csrf!` / `env.csrf_verified?` exist for route-level checks. Uses only stdlib crypto (`OpenSSL::HMAC`, `Crypto::Subtle`) — note `Crypto` must be written `::Crypto` here, since `Kemal::Session::Crypto` shadows it. This is the one file that `require "kemal"` (it reads `env.params`).
- **`ext/context.cr`** — monkey-patches `HTTP::Server::Context` to add lazily-memoized `env.session` and `env.flash`, plus the CSRF helpers (`env.csrf_token`, `env.csrf_hidden_field`, `env.csrf_meta_tags`, `env.csrf_verified?`, `env.verify_csrf!`) and the two per-request flags the handler owns (`session_deferred?`, `session_sent?`). `env.session?` returns the memoized session without building one, so committing never decrypts a cookie for a request that ignored the session.

### Session value API

Typed accessors are generated by the `typed_accessor` macro in `session.cr` for `int` (`Int64`, the width JSON integers already have in the store — there is no separate `bigint`)/`string`/`float`/`bool`, each producing `name(k)` (raises `KeyError`), `name?(k)` (nil-returning), and `name(k, v)` (set + persist). Because the store is flat, type guards on read mean a key written as one type reads back `nil`/raises as another, and `delete(k)` is type-agnostic. Complex values use `object(k, v)` to write and `object(k, as: Type)` / `object?(k, as: Type)` to read (round-tripped through `JSON::Serializable`; the `as:` keyword argument disambiguates the reader from the writer overload).

## Testing & Rails interop

Cross-language compatibility is verified two ways, both important when changing crypto:

- **Checked-in fixture** (`RailsFixture` in `spec/spec_helper.cr`): a genuine Rails 8 cookie + its known plaintext, proving read compatibility with **no** Ruby required. If you change key derivation or the wire format and this fixture stops decoding, the change broke Rails compat.
- **Live oracle** (`spec/support/oracle.rb`): a Ruby script using **real ActiveSupport** to encode/decode, exercised by `spec/rails_interop_spec.cr` in both directions. These specs call `require_oracle!`, which skips them (`pending!`) when Ruby/ActiveSupport is absent, so a passing local run does **not** guarantee interop was actually checked — confirm Ruby+ActiveSupport are present when touching crypto.
- **Live CSRF oracle** (`spec/support/csrf_oracle.rb`): drives the **real `ActionController::RequestForgeryProtection`** (masking/validation), exercised by `spec/csrf_interop_spec.cr` in both directions. Needs actionpack, not just activesupport, so it resolves gems through `bundler/inline` with `gemfile(false)` (installed gems only, no network) — a plain `require "action_controller"` blows up on gem activation conflicts in some rvm setups. Same skip caveat via `require_csrf_oracle!`. Both availability probes run once per suite (`ORACLE_AVAILABLE`/`CSRF_ORACLE_AVAILABLE`), since each costs a Ruby process.

Because `Config::INSTANCE` is a global singleton, specs reset it via `configure_session` in a `before_each` to avoid state leaking between examples.

Since a mutation without `Session::Handler` raises, `build_context` marks every context `session_deferred = true` (as if the handler ran) and specs call `session.commit` before asserting on `response.cookies`. `through_session_handler` runs a context through the real handler, and `session_handler_spec.cr` uses its own context builder that exposes the response `IO` — the only way to assert that `Set-Cookie` really reached the wire ahead of a body larger than the output buffer.

The other `spec_helper` builders keep the repetitive setup in one place: `reread(context)` turns the cookie a response just wrote into the next request, `build_context_with_cookie` seeds an incoming cookie, and for CSRF, `csrf_token_pair` mints a matching real/masked pair while `build_csrf_post` builds the `POST /items` that carries the masked token in `X-CSRF-Token` (pass `headers` for the `Origin`/forwarded-header cases).
