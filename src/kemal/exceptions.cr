module Kemal
  class Session
    VERSION = "0.1.0"

    # Base error type for everything raised by this shard.
    class Error < Exception
    end

    # Raised when a cryptographic operation is attempted but no secret has been
    # configured (see `Kemal::Session.config.secret`).
    class SecretRequiredException < Error
    end

    # Raised when an incoming cookie cannot be decrypted, is malformed, has been
    # tampered with, or carries the wrong purpose.
    class InvalidMessage < Error
    end

    # Raised when a message's embedded expiry (`exp`) is in the past.
    class ExpiredMessage < InvalidMessage
    end

    # Raised by `Session#save` when the cookie would exceed
    # `Session::MAX_COOKIE_SIZE` (the equivalent of Rails'
    # `ActionDispatch::Cookies::CookieOverflow`). Browsers drop an oversized
    # cookie silently, so without this the session would just vanish.
    #
    # Because the cookie is written once per request by `Session::Handler`, this
    # surfaces when the session is committed — as the response body starts —
    # rather than from the setter that made the session too big.
    class CookieOverflow < Error
    end

    # Raised when a request's session is mutated but `Session::Handler` is not
    # in the handler chain. Nothing would ever write the cookie, so the mutation
    # would be silently lost.
    class HandlerRequired < Error
    end

    # Raised when a request's session is mutated after the response body has
    # started, at which point the `Set-Cookie` header can no longer be changed
    # (the equivalent of Rails' `ActionDispatch::IllegalStateError`).
    class ResponseAlreadySent < Error
    end

    # Raised by `CSRF.verify!` when a request carries no valid authenticity token
    # (the equivalent of Rails' `ActionController::InvalidAuthenticityToken`).
    class InvalidAuthenticityToken < Error
    end
  end
end
