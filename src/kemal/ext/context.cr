require "http/server"

# Adds `env.session` and `env.flash` to Kemal handlers, matching kemal-session,
# plus the Rails-compatible CSRF helpers.
class HTTP::Server::Context
  @kemal_rails_session : Kemal::Session?
  @kemal_rails_flash : Kemal::Session::Flash?

  # Whether `Kemal::Session::Handler` is handling this request and will write the
  # cookie once, before the response body. Mutating a session without it raises
  # `Kemal::Session::HandlerRequired`, since nothing would write the cookie.
  property? session_deferred : Bool = false

  # Whether the session cookie for this request has already been handed to the
  # response. Lives on the context rather than the session because the response
  # can start before anything asks for a session — and a session built after
  # that point must refuse mutations just the same.
  property? session_sent : Bool = false

  # The session for this request. Lazily decrypts the incoming cookie.
  def session : Kemal::Session
    @kemal_rails_session ||= Kemal::Session.new(self)
  end

  # The session for this request *if* something already asked for one. Lets
  # `Kemal::Session::Handler` commit without decrypting a cookie for every
  # request that never touches the session.
  def session? : Kemal::Session?
    @kemal_rails_session
  end

  # The flash for this request.
  def flash : Kemal::Session::Flash
    @kemal_rails_flash ||= Kemal::Session::Flash.new(session)
  end

  # A masked authenticity token for this session, equivalent to Rails'
  # `form_authenticity_token`. Pass the form's *action* and *method* for a
  # per-form token.
  def csrf_token(action : String? = nil, method : String? = nil) : String
    Kemal::Session::CSRF.token(session, action, method, request.path)
  end

  # Rails' `csrf_meta_tags`, for pages whose JavaScript reads the token.
  def csrf_meta_tags : String
    Kemal::Session::CSRF.meta_tags(self)
  end

  # The hidden authenticity-token input for a form posting to *action*.
  def csrf_hidden_field(action : String? = nil, method : String? = "post") : String
    Kemal::Session::CSRF.hidden_field(self, action, method)
  end

  # Whether this request passes CSRF verification.
  def csrf_verified? : Bool
    Kemal::Session::CSRF.verified_request?(self)
  end

  # Verifies this request, raising `Kemal::Session::InvalidAuthenticityToken`
  # when it carries no valid token.
  def verify_csrf! : Nil
    Kemal::Session::CSRF.verify!(self)
  end
end
