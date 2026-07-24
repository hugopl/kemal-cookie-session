require "http/cookie"

module Kemal
  class Session
    # Configuration singleton. Mirrors the `kemal-session` config surface where
    # it makes sense for a client-side (cookie) store, plus a few Rails-specific
    # knobs (`salt`, `iterations`). `engine` / `gc_interval` from `kemal-session`
    # have no analogue here: the cookie *is* the storage.
    class Config
      # The Rails `secret_key_base`. Required; cryptographic operations raise
      # `SecretRequiredException` while this is empty.
      property secret : String = ""

      # Key-derivation salt. Defaults to Rails' authenticated-encrypted-cookie salt.
      property salt : String = "authenticated encrypted cookie"

      # PBKDF2 iteration count. Rails uses 1000 for its application key generator.
      property iterations : Int32 = 1000

      # Cookie name. Also determines the message purpose `cookie.<cookie_name>`.
      # Rails' default session key is `_session_id`.
      property cookie_name : String = "_session_id"

      # `false` is Rails' default too (it leans on `force_ssl`). Set it to `true`
      # for any app served over HTTPS, or the cookie also travels over plain HTTP.
      property secure : Bool = false

      property http_only : Bool = true
      property domain : String? = nil
      property path : String = "/"
      property samesite : HTTP::Cookie::SameSite? = HTTP::Cookie::SameSite::Lax

      # CSRF: whether per-form tokens are issued and accepted. Must match the Rails
      # app's `config.action_controller.per_form_csrf_tokens`, which is `true` under
      # `load_defaults 5.2` or later.
      property csrf_per_form_tokens : Bool = true

      # CSRF: whether the `Origin` header is checked against the request's base URL
      # (Rails' `config.action_controller.forgery_protection_origin_check`).
      property csrf_origin_check : Bool = true

      # CSRF: the request parameter carrying the token (Rails'
      # `config.action_controller.request_forgery_protection_token`).
      property csrf_param_name : String = "authenticity_token"

      # CSRF: whether `X-Forwarded-Proto` / `X-Forwarded-Host` are believed when
      # deriving the base URL the `Origin` header is compared against. `true`
      # matches Rails' `request.base_url`, and is safe behind a proxy that
      # overwrites those headers; set it to `false` when anything can reach the
      # app directly, so a spoofed forwarded host can't satisfy the check.
      # Ignored when `csrf_base_url` is set.
      property csrf_trust_forwarded_headers : Bool = true

      # CSRF: base URL the `Origin` header is compared against, e.g.
      # `"https://app.example.com"`. Derived from `X-Forwarded-Proto`/`Host` when
      # `nil`; set it explicitly when running behind a proxy that doesn't forward
      # the original scheme.
      property csrf_base_url : String? = nil

      # Optional cookie lifetime. `nil` (default) emits a session cookie with a
      # `null` metadata expiry, matching a default Rails session. When set, the
      # cookie gets an `Expires` and the metadata envelope an `exp`.
      property timeout : Time::Span? = nil

      INSTANCE = new

      @encryptor : MessageEncryptor?
      @encryptor_signature : Tuple(String, String, Int32)?

      # Rails-friendly alias for `secret`.
      def secret_key_base : String
        secret
      end

      def secret_key_base=(value : String) : String
        self.secret = value
      end

      # The message purpose Rails embeds/checks for this cookie.
      def purpose : String
        "cookie.#{cookie_name}"
      end

      # A cached `MessageEncryptor`, rebuilt when the secret/salt/iterations change.
      def encryptor : MessageEncryptor
        raise SecretRequiredException.new(
          "Kemal::Session.config.secret must be set (your Rails secret_key_base)"
        ) if secret.empty?

        signature = {secret, salt, iterations}
        cached = @encryptor
        return cached if cached && @encryptor_signature == signature

        @encryptor_signature = signature
        @encryptor = MessageEncryptor.from_secret(secret, salt, iterations)
      end
    end

    # Yields the config for block-style setup:
    # `Kemal::Session.config { |c| c.secret = "..." }`.
    def self.config(&) : Config
      yield Config::INSTANCE
      Config::INSTANCE
    end

    # Returns the config singleton.
    def self.config : Config
      Config::INSTANCE
    end
  end
end
