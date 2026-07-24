require "base64"
require "crypto/subtle"
require "openssl/hmac"
require "random/secure"
require "uri"
require "kemal"

module Kemal
  class Session
    # Rails-compatible CSRF ("authenticity token") support, built on the shared
    # session cookie.
    #
    # This is a port of `ActionController::RequestForgeryProtection` (actionpack
    # 8.1) with its `SessionStore` token strategy, so tokens are exchangeable in
    # both directions: a form rendered by Rails posts successfully to a Kemal
    # route and vice-versa. The pieces, all of which must stay byte-compatible:
    #
    # * the real token lives in the session at `_csrf_token`, encoded as unpadded
    #   urlsafe base64 of 32 random bytes (Rails' `SecureRandom.urlsafe_base64(32)`)
    # * a token handed to a client is *masked*: `raw = HMAC-SHA256(real, identifier)`,
    #   then `urlsafe_base64(pad + (pad XOR raw))` for a fresh 32-byte `pad`
    # * the identifier is `"!real_csrf_token"` for the global token, or
    #   `"<action_path>#<method>"` for a per-form token
    # * verification unmasks and accepts the global token, the real token, or the
    #   per-form token for the current path+method
    #
    # Only `GET` and `HEAD` skip verification — exactly like Rails, which does
    # *not* exempt `OPTIONS`/`TRACE`.
    module CSRF
      # Length of the raw (unmasked) token in bytes (Rails' `AUTHENTICITY_TOKEN_LENGTH`).
      TOKEN_LENGTH = 32

      # Session key used by Rails' `SessionStore` token strategy.
      SESSION_KEY = "_csrf_token"

      # Identifier Rails HMACs to derive the global (non-per-form) token.
      GLOBAL_IDENTIFIER = "!real_csrf_token"

      # Header inspected in addition to the request parameter.
      HEADER_NAME = "X-CSRF-Token"

      # Request methods that skip verification, matching Rails' `verified_request?`.
      SAFE_METHODS = %w[GET HEAD]

      # --- tokens -------------------------------------------------------------

      # The *encoded* real token from the session, generated and persisted when
      # absent (Rails' `real_csrf_token` plus its `commit_csrf_token` write).
      def self.real_token(session : Session) : String
        if existing = session.string?(SESSION_KEY)
          return existing
        end

        token = encode(Random::Secure.random_bytes(TOKEN_LENGTH))
        session.string(SESSION_KEY, token)
        token
      end

      # Drops the real token, so the next `real_token` call rotates it. Rails does
      # this on sign-in/sign-out (`reset_csrf_token`).
      def self.reset(session : Session) : Nil
        session.delete(SESSION_KEY)
      end

      # A masked token to hand to a client — the value Rails would render as
      # `form_authenticity_token`. Pass *action* and *method* to get a per-form
      # token (only honoured when `config.csrf_per_form_tokens` is on); *action*
      # may be relative, in which case *request_path* is used to resolve it.
      def self.token(session : Session, action : String? = nil, method : String? = nil,
                     request_path : String? = nil) : String
        real = decode?(real_token(session)) || Bytes.empty

        identifier =
          if Session.config.csrf_per_form_tokens && action && method
            per_form_identifier(action, method, request_path)
          else
            GLOBAL_IDENTIFIER
          end

        mask(hmac(real, identifier))
      end

      # Whether *token* is a valid authenticity token for *session*. *path* and
      # *method* are the current request's, needed to accept per-form tokens.
      def self.valid_token?(session : Session, token : String?, path : String? = nil,
                            method : String? = nil) : Bool
        return false if token.nil? || token.empty?

        # Rails would generate a real token here if the session had none; that
        # token cannot match anything the client already holds, so treat a
        # tokenless session as a failure.
        encoded_real = session.string?(SESSION_KEY)
        return false unless encoded_real

        masked = decode?(token)
        real = decode?(encoded_real)
        return false unless masked && real

        case masked.size
        when TOKEN_LENGTH
          # An unmasked token, as issued by pre-4.1 Rails.
          secure_compare(masked, real)
        when TOKEN_LENGTH * 2
          unmasked = unmask(masked)
          return true if secure_compare(unmasked, hmac(real, GLOBAL_IDENTIFIER))
          return true if secure_compare(unmasked, real)

          if Session.config.csrf_per_form_tokens && path && method
            secure_compare(unmasked, hmac(real, per_form_identifier(path, method)))
          else
            false
          end
        else
          false # malformed
        end
      end

      # --- request verification -----------------------------------------------

      # Whether this request passes CSRF verification: safe methods always do,
      # anything else needs a same-origin request carrying a valid token in the
      # `X-CSRF-Token` header or the authenticity-token parameter.
      def self.verified_request?(context : HTTP::Server::Context) : Bool
        return true if SAFE_METHODS.includes?(context.request.method)
        return false unless valid_origin?(context)

        path = context.request.path
        method = context.request.method
        each_request_token(context) do |token|
          return true if valid_token?(context.session, token, path, method)
        end
        false
      end

      # Like `verified_request?`, but raises `InvalidAuthenticityToken` on failure
      # (Rails' `protect_from_forgery with: :exception`).
      def self.verify!(context : HTTP::Server::Context) : Nil
        return if verified_request?(context)

        # Naming both URLs is what turns the usual origin failure — TLS
        # terminated at a proxy that doesn't forward the scheme, so every POST
        # is compared against an `http://` base URL — into a five-second fix.
        unless valid_origin?(context)
          raise InvalidAuthenticityToken.new(
            "CSRF verification failed for #{context.request.method} #{context.request.path}: " \
            "Origin #{context.request.headers["Origin"]?} doesn't match the base URL #{base_url(context)}"
          )
        end

        raise InvalidAuthenticityToken.new(
          "CSRF verification failed for #{context.request.method} #{context.request.path}"
        )
      end

      # Yields the candidate tokens carried by this request: the `X-CSRF-Token`
      # header plus the authenticity-token parameter from the query string, form
      # body or JSON body (Rails looks in the header and `params`).
      #
      # Each source is touched only when the iteration reaches it, and they are
      # ordered by what they cost to read. That matters beyond speed: parsing a
      # `multipart/form-data` body spools every file part to disk, so a request
      # that matches on the header never pays for — or leaves behind — an upload
      # it didn't need to look at.
      def self.each_request_token(context : HTTP::Server::Context, & : String ->) : Nil
        param = Session.config.csrf_param_name

        if header = context.request.headers[HEADER_NAME]?
          yield header
        end

        params = context.params
        if value = params.query[param]?
          yield value
        end
        if value = params.body[param]?
          yield value
        end
        if value = params.json[param]?.as?(String)
          yield value
        end
      end

      # The candidate tokens carried by this request, as an array. Reads every
      # source; `each_request_token` is the short-circuiting form.
      def self.request_tokens(context : HTTP::Server::Context) : Array(String)
        tokens = [] of String
        each_request_token(context) { |token| tokens << token }
        tokens
      end

      # Rails' `valid_request_origin?`: an absent `Origin` is accepted (some user
      # agents omit it), otherwise it must equal this request's base URL. Rails
      # *raises* on a literal `"null"` origin; here it simply fails the check.
      def self.valid_origin?(context : HTTP::Server::Context) : Bool
        return true unless Session.config.csrf_origin_check

        origin = context.request.headers["Origin"]?
        return true if origin.nil? || origin.empty?
        return false if origin == "null"

        origin == base_url(context)
      end

      # --- view helpers -------------------------------------------------------

      # Rails' `csrf_meta_tags`, so Turbo/Rails UJS on a Kemal-rendered page picks
      # the token up and sends it as `X-CSRF-Token`.
      def self.meta_tags(context : HTTP::Server::Context) : String
        param = Session.config.csrf_param_name
        %(<meta name="csrf-param" content="#{param}" />\n) +
          %(<meta name="csrf-token" content="#{token(context.session)}" />)
      end

      # The hidden input Rails' `form_with`/`form_tag` emits. *action* and *method*
      # are the form's, and enable a per-form token.
      def self.hidden_field(context : HTTP::Server::Context, action : String? = nil,
                            method : String? = nil) : String
        value = token(context.session, action, method, context.request.path)
        %(<input type="hidden" name="#{Session.config.csrf_param_name}" value="#{value}" autocomplete="off" />)
      end

      # --- middleware ---------------------------------------------------------

      # Verifies every unsafe request, raising `InvalidAuthenticityToken` when
      # verification fails. Protecting the whole app by default, and exempting
      # deliberately, is what Rails does — the route you forget to protect is the
      # one that gets abused.
      #
      #     use Kemal::Session::CSRF::Handler.new
      #
      # Register an error handler for the response, or Kemal renders its generic
      # 500 (the dev exception page outside production). Rails answers 422:
      #
      #     error Kemal::Session::InvalidAuthenticityToken do |env|
      #       env.response.status_code = 422
      #       "Invalid authenticity token"
      #     end
      #
      # Exempt the routes that cannot carry a token — a webhook, or an API
      # authenticated by a header rather than the session cookie (`except` entries
      # are matched against the request path: strings exactly, regexes by pattern):
      #
      #     use Kemal::Session::CSRF::Handler.new(except: ["/webhooks/stripe", /\A\/api\//])
      #
      # `skip` covers what a path can't express; returning `true` bypasses the check:
      #
      #     handler = Kemal::Session::CSRF::Handler.new
      #     handler.skip = ->(env : HTTP::Server::Context) do
      #       !!env.request.headers["Authorization"]?.try(&.starts_with?("Bearer "))
      #     end
      #     use handler
      class Handler
        include HTTP::Handler

        # Request paths that bypass verification.
        property except : Array(String | Regex)

        # Extra bypass predicate, consulted when `except` doesn't match.
        property skip : Proc(HTTP::Server::Context, Bool)?

        def initialize(@except : Array(String | Regex) = [] of String | Regex)
        end

        def call(context : HTTP::Server::Context)
          verify(context) unless exempt?(context)
          call_next(context)
        end

        # Kemal spools multipart file parts to `Dir.tempdir` and deletes them in
        # `RouteHandler#process_request`'s `ensure` — which never runs if we
        # raise before `call_next`. Without this, every rejected upload would
        # leave its temp files behind.
        private def verify(context : HTTP::Server::Context) : Nil
          CSRF.verify!(context)
        rescue ex
          context.params.cleanup_temporary_files
          raise ex
        end

        private def exempt?(context : HTTP::Server::Context) : Bool
          path = context.request.path
          return true if @except.any? { |matcher| matcher === path }

          if skip = @skip
            skip.call(context)
          else
            false
          end
        end
      end

      # --- internals ----------------------------------------------------------

      # Rails' `mask_token`: XOR the raw token with a fresh one-time pad and ship
      # both, so the value differs per response (BREACH mitigation).
      private def self.mask(raw : Bytes) : String
        pad = Random::Secure.random_bytes(TOKEN_LENGTH)
        masked = Bytes.new(TOKEN_LENGTH * 2)
        pad.copy_to(masked)
        xor(pad, raw).copy_to(masked + TOKEN_LENGTH)
        encode(masked)
      end

      private def self.unmask(masked : Bytes) : Bytes
        xor(masked[0, TOKEN_LENGTH], masked[TOKEN_LENGTH, masked.size - TOKEN_LENGTH])
      end

      # Both operands are always `TOKEN_LENGTH` bytes here — the pad and the HMAC
      # in `mask`, the two halves of a `TOKEN_LENGTH * 2` token in `unmask`. The
      # sizes are checked anyway because the failure modes are bad in both
      # directions: a shorter *a* raises a bare `IndexError` from inside a
      # masking routine, and a longer one silently masks against a truncated pad.
      private def self.xor(a : Bytes, b : Bytes) : Bytes
        unless a.size == b.size
          raise ArgumentError.new("xor operands must be the same size, got #{a.size} and #{b.size}")
        end

        out = Bytes.new(b.size)
        b.each_with_index { |byte, i| out[i] = byte ^ a[i] }
        out
      end

      private def self.hmac(key : Bytes, identifier : String) : Bytes
        OpenSSL::HMAC.digest(:sha256, key, identifier)
      end

      private def self.secure_compare(a : Bytes, b : Bytes) : Bool
        return false unless a.size == b.size
        # Fully qualified: `Crypto` alone would resolve to `Kemal::Session::Crypto`.
        ::Crypto::Subtle.constant_time_compare(a, b)
      end

      private def self.encode(bytes : Bytes) : String
        Base64.urlsafe_encode(bytes, padding: false)
      end

      # Tolerant of both the urlsafe and the standard alphabet, padded or not,
      # like Ruby's `Base64.urlsafe_decode64`.
      private def self.decode?(value : String) : Bytes?
        Base64.decode(value)
      rescue Base64::Error
        nil
      end

      # Rails' `normalize_action_path`: strip query/fragment, drop a trailing
      # slash, and resolve a relative action against the current request path.
      def self.normalize_action_path(action : String, request_path : String? = nil) : String
        uri = URI.parse(action)
        path = uri.path

        if uri.scheme.nil? && uri.host.nil? && !action.starts_with?('/')
          path = "#{request_path || ""}/#{path}".gsub("/./", "/")
        end

        path.chomp("/")
      rescue URI::Error
        action.chomp("/")
      end

      # The identifier Rails HMACs for a per-form token. Both sides of the
      # exchange go through here — the issuing side with the form's action, the
      # verifying side with the request path — so the two can't drift apart.
      private def self.per_form_identifier(action : String, method : String,
                                           request_path : String? = nil) : String
        "#{normalize_action_path(action, request_path)}##{method.downcase}"
      end

      private def self.base_url(context : HTTP::Server::Context) : String
        if configured = Session.config.csrf_base_url
          return configured
        end

        headers = context.request.headers

        if Session.config.csrf_trust_forwarded_headers
          scheme = first_forwarded(headers["X-Forwarded-Proto"]?) || "http"
          host = first_forwarded(headers["X-Forwarded-Host"]?) || headers["Host"]? || ""
        else
          scheme = "http"
          host = headers["Host"]? || ""
        end

        "#{scheme}://#{host}"
      end

      private def self.first_forwarded(value : String?) : String?
        return nil unless value
        first = value.split(',').first.strip
        first.empty? ? nil : first
      end
    end
  end
end
