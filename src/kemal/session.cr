require "http/server"
require "json"
require "uri"
require "random/secure"

module Kemal
  # A cookie-store session for Kemal: the entire session lives inside a single
  # AES-256-GCM encrypted, tamper-proof cookie. Nothing is stored server-side —
  # there is no storage engine, no session id registry, and no GC.
  #
  # Unlike `kemal-session` (a server-side store keyed by a signed id), this keeps
  # all session data in the cookie itself; the public value API is kept
  # compatible with `kemal-session`. As a bonus, the cookie's wire format is
  # byte-compatible with Rails' `ActionDispatch::Session::CookieStore`, so a
  # Kemal and a Rails 8 app can share sessions.
  #
  # The session hash is *flat*, so a key lives in a single namespace rather than
  # one-per-type: `session.int("n", 1)` and `session.string("n", "x")` refer to
  # the same key `"n"`.
  class Session
    # The largest cookie browsers are required to accept, and the limit Rails
    # enforces (`ActionDispatch::Cookies::MAX_COOKIE_SIZE`).
    MAX_COOKIE_SIZE = 4096

    # The underlying flat session hash. Values Rails would set are visible here
    # and vice-versa.
    getter store : Hash(String, JSON::Any)

    # Whether `#destroy` was called on this session. A destroyed session still
    # works in memory for the rest of the request, but never writes a live
    # cookie again — only `#reset` starts a new one.
    getter? destroyed : Bool = false

    # Whether the store has been mutated since the cookie was last written.
    # Mutations only mark the session dirty; `Session::Handler` encrypts and
    # writes the cookie once per request (see `#commit`).
    getter? dirty : Bool = false

    @context : HTTP::Server::Context?

    # Builds a session from a request context, decrypting the incoming cookie
    # (if present and valid). An invalid/tampered cookie yields an empty session.
    def initialize(context : HTTP::Server::Context)
      @context = context
      @store = read_cookie(context) || empty_store
    end

    # Builds a detached, empty session (no cookie is written).
    def initialize
      @context = nil
      @store = empty_store
    end

    # The `session_id`. Generated (and persisted to the cookie) on first
    # access if not already present.
    def id : String
      if existing = @store["session_id"]?.try(&.as_s?)
        return existing
      end

      new_id = Random::Secure.hex(16)
      @store["session_id"] = JSON::Any.new(new_id)
      touch
      new_id
    end

    # Clears the session and expires the cookie. The cookie *stays* expired for
    # the rest of the request: anything that repopulates the store afterwards
    # (a layout rendering `csrf_meta_tags` after a logout, say) would otherwise
    # save a fresh live cookie and undo the call.
    def destroy : Nil
      @destroyed = true
      @store.clear
      touch
    end

    # Clears all data and starts a fresh session (new `session_id`). This
    # deliberately starts a new session, so it lifts a previous `#destroy`.
    def reset : Nil
      @destroyed = false
      @store.clear
      id
    end

    # Writes the cookie for this request, if the session was mutated, and marks
    # the session as sent — after which further mutations raise
    # `ResponseAlreadySent`.
    #
    # `Session::Handler` calls this immediately before the first byte of the
    # response body (the last moment the `Set-Cookie` header can still change),
    # and again for responses that end without a body. Calling it twice is
    # harmless: the second call has nothing to write.
    def commit : Nil
      save if @dirty
      @context.try(&.session_sent = true)
    end

    # Whether the cookie for this request has already been handed to the
    # response. Past that point the `Set-Cookie` header is fixed, so further
    # mutations raise rather than being lost.
    def sent? : Bool
      !!@context.try(&.session_sent?)
    end

    # Serializes and re-encrypts the session into the response cookie. Prefer
    # letting `Session::Handler` do this once per request via `#commit`; calling
    # it directly writes the cookie immediately, which only works while the
    # response body has not started. A no-op for detached sessions.
    #
    # A session that has become empty — or that was destroyed — expires the
    # cookie rather than leaving the last value the client was given in place;
    # otherwise deleting the final key (a hand-rolled logout) would silently
    # keep the old session alive.
    #
    # Raises `CookieOverflow` if the session no longer fits in a cookie. The
    # dirty flag is cleared first, so an overflowing session raises once, from
    # whichever call tried to write it, rather than again from every later
    # commit.
    def save : Nil
      context = @context
      @dirty = false
      return unless context

      if @destroyed || @store.empty?
        expire_cookie(context)
        return
      end

      name = Session.config.cookie_name
      value = encode

      # Measured exactly as Rails' `check_for_overflow!` does: the cookie name
      # plus the raw encrypted value, before any URL escaping.
      size = name.bytesize + value.bytesize
      raise CookieOverflow.new("#{name} cookie overflowed with size #{size} bytes") if size > MAX_COOKIE_SIZE

      context.response.cookies[name] = build_cookie(URI.encode_www_form(value), expires_at)
    end

    # The raw (unescaped) encrypted cookie value for the current store.
    def encode : String
      Session.config.encryptor.encrypt_and_sign(@store.to_json, Session.config.purpose, expires_at)
    end

    # --- Typed value accessors (kemal-session compatible) -------------------

    # Generates, for a given name/Crystal-type:
    #   name(k)          -> value            (raises KeyError if absent/wrong type)
    #   name?(k)         -> value?           (nil if absent/wrong type)
    #   name(k, v)       -> v                (set + persist)
    #
    # Deletion is type-agnostic (the store is flat): see `#delete`.
    macro typed_accessor(name, type, guard, read, write)
      def {{name.id}}(key : String) : {{type}}
        value = @store[key]?
        unless value && ({{guard}})
          raise KeyError.new("Session has no {{name.id}} value at #{key.inspect}")
        end
        value.{{read.id}}
      end

      def {{name.id}}?(key : String) : {{type}}?
        value = @store[key]?
        return nil unless value && ({{guard}})
        value.{{read.id}}
      end

      def {{name.id}}(key : String, value : {{type}}) : {{type}}
        @store[key] = {{write}}
        touch
        value
      end
    end

    # `int` is `Int64` — the width JSON integers already have in the store — so
    # no stored integer is ever too wide to read back.
    typed_accessor(int, Int64, value.raw.is_a?(Int), as_i64, JSON::Any.new(value))
    # `float` stays strict: a whole number is an integer, not a float. Widening
    # the guard to `Int | Float` would break the guard symmetry the flat store
    # relies on, since `int?` would still reject `5.0`.
    typed_accessor(float, Float64, value.raw.is_a?(Float64), as_f, JSON::Any.new(value))
    typed_accessor(string, String, value.raw.is_a?(String), as_s, JSON::Any.new(value))
    typed_accessor(bool, Bool, value.raw.is_a?(Bool), as_bool, JSON::Any.new(value))

    # Stores any JSON-serializable value (a `JSON::Serializable` object, an
    # `Array`/`Hash` of them, or a primitive) under `key` and persists.
    #
    #     session.object("cart", cart)
    def object(key : String, value : T) : T forall T
      @store[key] = JSON.parse(value.to_json)
      touch
      value
    end

    # Reads back a complex value, reconstructing it as `type`. `as` is a
    # keyword argument so this never collides with the writer overload.
    # Raises `KeyError` if the key is absent.
    #
    #     session.object("cart", as: Cart)
    #     session.object("items", as: Array(Item))
    def object(key : String, *, as type : T.class) : T forall T
      value = @store[key]?
      raise KeyError.new("Session has no object at #{key.inspect}") unless value
      T.from_json(value.to_json)
    end

    # Like `#object`, but returns `nil` when the key is absent or the stored
    # value cannot be reconstructed as `type`.
    def object?(key : String, *, as type : T.class) : T? forall T
      value = @store[key]?
      return nil unless value
      T.from_json(value.to_json)
    rescue JSON::ParseException | ArgumentError
      nil
    end

    # Removes a key from the session (regardless of value type) and persists.
    def delete(key : String) : Nil
      if @store.has_key?(key)
        @store.delete(key)
        touch
      end
    end

    # --- internals ----------------------------------------------------------

    # Records that the store changed, leaving the encryption to `#commit`. This
    # is the only reason a mutation is cheap: 100 setters cost one encryption,
    # not 100.
    #
    # A session bound to a request needs `Session::Handler` to do that commit,
    # and needs the response body not to have started yet; both failures lose
    # the mutation silently, so both raise. Detached sessions never write a
    # cookie and are exempt.
    private def touch : Nil
      context = @context
      return unless context

      unless context.session_deferred?
        raise HandlerRequired.new(
          "Session mutated without Kemal::Session::Handler in the handler chain — " \
          "the cookie would never be written. Add `use Kemal::Session::Handler.new` " \
          "before `Kemal.run`.")
      end

      if context.session_sent?
        raise ResponseAlreadySent.new(
          "Session mutated after the response body started, when the Set-Cookie " \
          "header can no longer change. Mutate the session before writing the response.")
      end

      @dirty = true
    end

    private def empty_store : Hash(String, JSON::Any)
      Hash(String, JSON::Any).new
    end

    private def expires_at : Time?
      Session.config.timeout.try { |span| Time.utc + span }
    end

    private def read_cookie(context : HTTP::Server::Context) : Hash(String, JSON::Any)?
      cookie = context.request.cookies[Session.config.cookie_name]?
      return nil unless cookie

      raw = URI.decode_www_form(cookie.value)
      payload = Session.config.encryptor.decrypt_and_verify(raw, Session.config.purpose)
      parsed = JSON.parse(payload)

      store = empty_store
      parsed.as_h.each { |key, value| store[key] = value }
      store
    rescue InvalidMessage | JSON::ParseException | TypeCastError
      nil
    end

    # The single place a session cookie is built — a live one and the expired one
    # that deletes it differ only in value and expiry, and every other attribute
    # has to match for the browser to treat them as the same cookie.
    private def build_cookie(value : String, expires : Time?) : HTTP::Cookie
      config = Session.config
      HTTP::Cookie.new(
        name: config.cookie_name,
        value: value,
        path: config.path,
        domain: config.domain,
        secure: config.secure,
        http_only: config.http_only,
        samesite: config.samesite,
        expires: expires,
      )
    end

    # Expires the client's cookie, but only when there is one to expire: either
    # the request carried it, or this response has already set it.
    private def expire_cookie(context : HTTP::Server::Context) : Nil
      name = Session.config.cookie_name
      return unless context.request.cookies.has_key?(name) || context.response.cookies.has_key?(name)
      context.response.cookies[name] = expired_cookie
    end

    private def expired_cookie : HTTP::Cookie
      build_cookie("", Time.unix(0))
    end
  end
end
