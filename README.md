# kemal-cookie-session

A **cookie-store session for [Kemal](https://kemalcr.com)**: the entire session
lives inside a single **AES-256-GCM encrypted, tamper-proof cookie**, with
**nothing stored server-side** — no storage engine, no session registry, no GC.

The public API mirrors the [`kemal-session`](https://github.com/kemalcr/kemal-session)
shard, so it's a drop-in replacement for the common cases.

As a bonus, the cookie's wire format is **byte-compatible with Rails 8's
`ActionDispatch::Session::CookieStore`**, so a Kemal app and a Rails 8 app that
share the same `secret_key_base` and cookie name can read and write each other's
sessions.

> ⚠️ **Cannot be used at the same time as `kemal-session`** — both define
> `Kemal::Session` and `env.session`. Pick one.

## How it differs from `kemal-session`

`kemal-session` is a *server-side* store: the cookie holds only a signed session
id and the data lives in a storage engine (memory/file/redis). This shard is a
*client-side* store: the entire session lives **inside the encrypted cookie**,
exactly like Rails. Consequences:

- The session hash is **flat** (Rails-shaped). A key lives in one namespace, not
  one-per-type: `session.int("n", 1)` and `session.string("n", "x")` refer to
  the same key `"n"`.
- There is **no storage engine and no GC**, so `config.engine` / `config.gc_interval`
  and the server-side, id-based lookup/enumeration methods from `kemal-session`
  (`Session.all`, `Session.get(id)`, `Session.each`, `Session.destroy(id)`,
  `Session.destroy_all`) have no meaning here and are omitted.
- Session data is limited to what fits in a cookie (4096 bytes, enforced — see
  [Rails compatibility details](#rails-compatibility-details)) and is visible to
  / stored by the client (encrypted + authenticated, so it can't be read or
  forged without the secret).
- Writing the session means writing a header, so it happens once per request via
  a required handler (`use Kemal::Session::Handler.new`) rather than on
  every assignment — see [When the cookie is written](#when-the-cookie-is-written).

## Installation

```yaml
dependencies:
  kemal-cookie-session:
    github: hugopl/kemal-cookie-session
```

Then `shards install`.

## Usage

```crystal
require "kemal"
require "kemal-cookie-session"

Kemal::Session.config do |c|
  c.secret      = ENV["SECRET_KEY_BASE"] # your Rails secret_key_base
  c.cookie_name = "_myapp_session"       # must match Rails `config.session_store key:`
end

# Required: writes the session cookie once per request. Without it, mutating a
# session raises `Kemal::Session::HandlerRequired`.
use Kemal::Session::Handler.new

get "/" do |env|
  count = env.session.int?("count") || 0_i64
  env.session.int("count", count + 1)
  "You have visited #{count + 1} times"
end

post "/login" do |env|
  env.session.int("user_id", 42)
  env.session.bool("admin", true)
  env.redirect "/"
end

get "/logout" do |env|
  env.session.destroy
  env.redirect "/"
end

Kemal.run
```

### Sharing sessions with a Rails 8 app

Use the same secret and cookie name on both sides:

```ruby
# Rails: config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store, key: "_myapp_session"
# SECRET_KEY_BASE must be identical to the Kemal app's `config.secret`.
```

A value written in Kemal as `env.session.int("user_id", 42)` is readable in
Rails as `session[:user_id] == 42`, and vice-versa.

## API

### Configuration (`Kemal::Session.config`)

| Option        | Type                      | Default                            |
|---------------|---------------------------|------------------------------------|
| `secret`      | `String`                  | `""` (required)                    |
| `cookie_name` | `String`                  | `"_session_id"`                    |
| `salt`        | `String`                  | `"authenticated encrypted cookie"` |
| `iterations`  | `Int32`                   | `1000`                             |
| `timeout`     | `Time::Span?`             | `nil`                              |
| `secure`      | `Bool`                    | `false`                            |
| `http_only`   | `Bool`                    | `true`                             |
| `domain`      | `String?`                 | `nil`                              |
| `path`        | `String`                  | `"/"`                              |
| `samesite`    | `HTTP::Cookie::SameSite?` | `Lax`                              |

CSRF-specific options (see [CSRF](#csrf-rails-authenticity-tokens)):

| Option                          | Type      | Default                |
|---------------------------------|-----------|------------------------|
| `csrf_per_form_tokens`          | `Bool`    | `true`                 |
| `csrf_origin_check`             | `Bool`    | `true`                 |
| `csrf_param_name`               | `String`  | `"authenticity_token"` |
| `csrf_trust_forwarded_headers`  | `Bool`    | `true`                 |
| `csrf_base_url`                 | `String?` | `nil`                  |

Per-option notes:

- `secret` — your Rails `secret_key_base`. Also aliased as `secret_key_base`.
- `cookie_name` — Rails session key; drives the message purpose `cookie.<name>`.
- `salt` — Rails’ default authenticated-encrypted-cookie salt.
- `iterations` — PBKDF2 iteration count (Rails’ app key generator default).
- `timeout` — `nil` emits a session cookie with a `null` metadata expiry
  (matches default Rails); when set, adds an `Expires` and a metadata `exp`.
- `secure` — `false`, the same default as Rails, which leans on `force_ssl`
  instead. Set it to `true` for any app served over HTTPS: without it the
  session cookie is sent over plain HTTP too, where it can be captured.
- `csrf_per_form_tokens` — must match the Rails app’s
  `config.action_controller.per_form_csrf_tokens` (`true` under
  `load_defaults 5.2` or later).
- `csrf_origin_check` — Rails’ `forgery_protection_origin_check`.
- `csrf_param_name` — Rails’ `request_forgery_protection_token`.
- `csrf_trust_forwarded_headers` — whether `X-Forwarded-Proto` /
  `X-Forwarded-Host` are believed when deriving the base URL the `Origin` header
  is compared against. `true` matches Rails’ `request.base_url` and is safe
  behind a proxy that overwrites those headers; set it to `false` if anything
  can reach the app directly, so a spoofed forwarded host can’t satisfy the
  check. Ignored when `csrf_base_url` is set.
- `csrf_base_url` — what the `Origin` header is compared against, e.g.
  `"https://app.example.com"`. Derived from `X-Forwarded-Proto`/`Host` when
  `nil`; set it explicitly if your proxy doesn’t forward the original scheme —
  otherwise the scheme falls back to `http` and every POST fails the check
  (the raised message names both URLs it compared).

### Session values (kemal-session compatible)

For each of `int` (Int64), `string`, `float` (Float64) and `bool`:

```crystal
env.session.int("k")    # => Int64   (raises KeyError if absent/wrong type)
env.session.int?("k")   # => Int64?  (nil if absent/wrong type)
env.session.int("k", 1) # set + persist
env.session.delete("k") # delete a key (type-agnostic, since the store is flat)
```

A whole number is an integer, not a float, so `float?` returns nil for one.

> **Note:** unlike `kemal-session`, the plural bulk accessors (`ints`,
> `strings`, `bools`, …) are **not** provided. Because the store is flat and
> Rails-shaped rather than namespaced per type, iterate `env.session.store`
> (a `Hash(String, JSON::Any)`) directly if you need every value.

### Complex objects

Anything that serializes to JSON — a `JSON::Serializable` object, an `Array` or
`Hash` of them, a primitive — goes in with `object` and comes back out with the
`as:` keyword:

```crystal
struct Cart
  include JSON::Serializable
  # ...
end

env.session.object("cart", cart)              # store (serialized as nested JSON)
env.session.object("cart", as: Cart)          # => Cart  (raises KeyError if absent)
env.session.object?("cart", as: Cart)         # => Cart? (nil if absent/incompatible)
env.session.object("items", as: Array(Item))  # any type with `from_json`
env.session.delete("cart")                    # deletion is type-agnostic
```

This differs from `kemal-session`, which stores objects in a type-tagged
container behind the `Kemal::Session::StorableObject` mixin. Here the value is
stored as plain nested JSON, so Rails sees an ordinary nested Hash under
`session[:cart]` — and the reader takes the class instead of consulting a global
type registry.

### Lifecycle

```crystal
env.session.id         # the Rails `session_id` (generated on first use)
env.session.destroy    # clear + expire the cookie
env.session.destroyed? # true once destroyed, until reset
env.session.reset      # clear + new session_id (lifts a previous destroy)
env.session.store      # the underlying Hash(String, JSON::Any)
```

`destroy` is sticky: the cookie stays expired for the rest of the request even if
something repopulates the session afterwards — a logout handler rendering a
layout with `csrf_meta_tags`, say. Use `reset` when you want a fresh session
rather than none.

### When the cookie is written

`Kemal::Session::Handler` writes it, once, immediately before the response body —
so a route that sets twenty keys pays for one encryption, not twenty. Mutations
in between only mark the session dirty.

```crystal
use Kemal::Session::Handler.new   # before any handler that uses the session
```

Two things raise rather than losing a session silently:

- **`HandlerRequired`** — the session was mutated with no handler in the chain,
  so nothing would ever have written the cookie.
- **`ResponseAlreadySent`** — the session was mutated after the response body
  started. `Set-Cookie` is a header, so it cannot change once the first bytes are
  out; mutate the session before writing the response. (Rails raises
  `ActionDispatch::IllegalStateError` here for the same reason.)

Because the write is deferred, `CookieOverflow` surfaces at that commit rather
than from the setter that made the session too big. `env.session.save` still
writes immediately if you need it — useful only before the body starts.

### Flash

A minimal, read-once flash (kemal-session compatible; **not** Rails' FlashHash):

```crystal
env.flash["notice"] = "Saved!"
env.flash["notice"]? # => "Saved!" (then nil on the next read)
```

### CSRF (Rails authenticity tokens)

A port of `ActionController::RequestForgeryProtection` with its `SessionStore`
token strategy, so authenticity tokens are exchangeable with Rails in both
directions: a form rendered by Rails posts successfully to a Kemal route, and a
form rendered by Kemal posts successfully to a Rails controller.

Verifying incoming requests. Prefer the handler: protecting everything by default
and exempting deliberately is what Rails does, and it means a new route is safe
before you remember it exists.

```crystal
use Kemal::Session::CSRF::Handler.new

# The handler raises; you choose the response. Rails answers 422 — without an
# error handler Kemal renders its generic 500 (the exception page outside production).
error Kemal::Session::InvalidAuthenticityToken do |env|
  env.response.status_code = 422
  "Invalid authenticity token"
end
```

`GET` and `HEAD` are exempt (and, exactly like Rails, `OPTIONS`/`TRACE` are
**not**). Tokens are read from the `X-CSRF-Token` header and from the
`authenticity_token` parameter in the body, query string or JSON body.
Verification fails closed: a request with no session cookie has no token to
match, so it is rejected.

Routes that genuinely can't carry a token — a webhook, or an API authenticated by
a header instead of the session cookie — are exempted explicitly. `except`
matches the request path (strings exactly, regexes by pattern), and `skip` covers
what a path can't express:

```crystal
handler = Kemal::Session::CSRF::Handler.new(except: ["/webhooks/stripe", /\A\/api\//])
handler.skip = ->(env : HTTP::Server::Context) do
  !!env.request.headers["Authorization"]?.try(&.starts_with?("Bearer "))
end
use handler
```

For a one-off check inside a route — or when you'd rather handle the failure
yourself — the request-level API is still there:

```crystal
post "/items" do |env|
  env.verify_csrf!    # raises Kemal::Session::InvalidAuthenticityToken
  # ...or: return unless env.csrf_verified?
end
```

Issuing tokens for pages Kemal renders:

```crystal
env.csrf_token                                   # masked global token
env.csrf_token(action: "/items", method: "post") # per-form token
env.csrf_hidden_field("/items", "post")          # <input type="hidden" ...>
env.csrf_meta_tags                               # <meta name="csrf-token" ...> for Turbo
```

Rotate the token after a privilege change (Rails' `reset_csrf_token`):

```crystal
Kemal::Session::CSRF.reset(env.session)
```

How it works, all of it byte-compatible with Rails:

- the real token lives in the session at `_csrf_token`, as unpadded urlsafe
  base64 of 32 random bytes (`SecureRandom.urlsafe_base64(32)`);
- a token handed to a client is *masked* — `raw = HMAC-SHA256(real, identifier)`,
  emitted as `urlsafe_base64(pad + (pad XOR raw))` with a fresh 32-byte pad, so
  the value differs per response (BREACH mitigation);
- `identifier` is `"!real_csrf_token"` for a global token, or
  `"<action_path>#<method>"` for a per-form token;
- verification unmasks and accepts the global token, the real token, or the
  per-form token for the current path and method.

## Rails compatibility details

The cookie is produced/consumed exactly as Rails 8 does by default:

- **Key**: `PBKDF2-HMAC-SHA1(secret_key_base, "authenticated encrypted cookie", 1000)` → 32 bytes.
- **Cipher**: AES-256-GCM, 12-byte IV, 16-byte auth tag, no AAD.
- **Wire**: `strict_base64(ciphertext)--strict_base64(iv)--strict_base64(tag)`, then CGI/URL-escaped in the header.
- **Plaintext**: the legacy metadata envelope
  `{"_rails":{"message":"<base64(session_json)>","exp":<iso8601|null>,"pur":"cookie.<key>"}}`.
- **Serializer**: JSON (`cookies_serializer = :json`).
- **Size limit**: 4096 bytes, measured like Rails' `check_for_overflow!` — the
  cookie name plus the raw encrypted value, before URL escaping. Past it, `save`
  raises `Kemal::Session::CookieOverflow` (Rails' `CookieOverflow`) rather than
  emitting a cookie the browser would silently drop.

This is verified by the test suite both against a checked-in genuine Rails 8
fixture and, when Ruby + ActiveSupport are installed, against a live oracle in
both directions.

CSRF tokens are verified the same way, against a live oracle driving the real
`ActionController::RequestForgeryProtection` (needs Ruby + actionpack; skipped
automatically when absent).

## Development

```
crystal spec        # runs unit + interop specs (interop auto-skips without Ruby/ActiveSupport)
crystal tool format
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Hugo Parente Lima](https://github.com/your-github-user) - creator and maintainer

## License

MIT
