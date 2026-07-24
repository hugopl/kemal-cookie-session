require "spec"
require "file_utils"
require "http/formdata"
require "../src/kemal-cookie-session"

# A complex value used to exercise the `#object` accessor.
class Cart
  include JSON::Serializable
  getter items : Array(String)
  getter total : Float64

  def initialize(@items : Array(String), @total : Float64)
  end
end

# A genuine Rails 8 (ActiveSupport 8.1) encrypted session cookie, generated with
# the exact cookie-jar configuration (aes-256-gcm, NullSerializer, PBKDF2-HMAC-SHA1
# iterations=1000, salt "authenticated encrypted cookie", cookies_serializer=:json,
# purpose "cookie.<key>"). Used to prove read compatibility without a running Rails.
module RailsFixture
  SECRET     = "b1d8e0b3f4c2a7e6d5c4b3a2918079685746352413029f8e7d6c5b4a39281706"
  COOKIE_KEY = "_myapp_session"
  SALT       = "authenticated encrypted cookie"

  # PBKDF2-HMAC-SHA1(SECRET, SALT, 1000, 32), as produced by ActiveSupport::KeyGenerator.
  KEY_HEX = "fba72d2543c2adce00b01628c9a18b71f8c62c21b8b8cecfe3fe150f7fe0b50a"

  # The URL(CGI)-escaped cookie value exactly as Rack would place it on the wire.
  COOKIE_WIRE = "ncLbJuhnu62X5OWtgtGedaLBlxYA%2FlOEkk4zOraeoc83%2Bb9ueQIRIT7j%2BdOqrGfyOr5aza2ZF6K4y9sqhAOGtXvxWFq4B0JbpnEQ9pdOxUacLQrWmtQh7IpiEs9MalH8jMYBZkUfDo%2BynfnxbNDu782Jn34MCPDYTCmqE5CfLme7MW6YVdc4aMb7sJnia7XqCPPEgJpbzccRdMeRo4WUPpLFCmQLwobBLZruP33VTiBcvJ%2BvRQ3DSVbMXjWZ0Six%2BKpfr6JsInsKl215TV2B6m%2Bji4dlJnyDiiaxRdFnSuYYmErYEIoIRSX4VEP0WSkt2WXhUxpBsawSZrZvCfBzL5ninKLS%2BDpqR0X7GPnrcSmAJYwudJ8%3D--ioZK1b1f%2BTHV1IfP--WpROXYYJ%2BvsCLqqW3Z%2Fd8g%3D%3D"
end

# Resets the session config to defaults with a given secret/cookie name so
# examples don't leak state into each other.
def configure_session(cookie_name : String = "_session_id", secret : String = RailsFixture::SECRET) : Nil
  config = Kemal::Session.config
  config.secret = secret
  config.salt = "authenticated encrypted cookie"
  config.iterations = 1000
  config.cookie_name = cookie_name
  config.timeout = nil
  config.secure = false
  config.http_only = true
  config.domain = nil
  config.path = "/"
  config.samesite = HTTP::Cookie::SameSite::Lax
  config.csrf_per_form_tokens = true
  config.csrf_origin_check = true
  config.csrf_param_name = "authenticity_token"
  config.csrf_trust_forwarded_headers = true
  config.csrf_base_url = nil
end

# Builds a fresh request/response context, optionally seeded with a Cookie header.
def build_context(cookie_header : String? = nil, method : String = "GET", path : String = "/",
                  body : String? = nil, content_type : String? = nil,
                  headers : HTTP::Headers = HTTP::Headers.new) : HTTP::Server::Context
  headers["Cookie"] = cookie_header if cookie_header
  headers["Content-Type"] = content_type if content_type
  request = HTTP::Request.new(method, path, headers, body)
  response = HTTP::Server::Response.new(IO::Memory.new)
  context = HTTP::Server::Context.new(request, response)
  # A session refuses to be mutated unless `Session::Handler` is in the chain,
  # so every built context claims to be handled. Specs that exercise the handler
  # itself use `through_session_handler`; the one that checks the refusal turns
  # this back off.
  context.session_deferred = true
  context
end

# Runs *context* through a real `Session::Handler`, yielding inside the chain, so
# the session is committed exactly as it would be under Kemal.
def through_session_handler(context : HTTP::Server::Context, &block : HTTP::Server::Context ->) : Nil
  handler = Kemal::Session::Handler.new
  handler.next = block
  handler.call(context)
end

# A `multipart/form-data` body with one file part, returned with its
# Content-Type. Kemal spools every file part to `Dir.tempdir`, so this is the
# body shape that makes parsing expensive — and leaky.
def multipart_upload(file_size : Int32 = 16 * 1024) : {String, String}
  boundary = "KemalCookieSessionSpecBoundary"
  io = IO::Memory.new
  HTTP::FormData.build(io, boundary) do |builder|
    builder.field("name", "widget")
    builder.file("upload", IO::Memory.new("a" * file_size),
      HTTP::FormData::FileMetadata.new(filename: "payload.bin"))
  end
  {io.to_s, "multipart/form-data; boundary=#{boundary}"}
end

# Runs the block with `Dir.tempdir` pointed at an empty directory (yielded), so
# a spec can tell exactly what was spooled there and what was cleaned up.
def with_empty_tempdir(&)
  previous = ENV["TMPDIR"]?
  dir = File.tempname("kemal-cookie-session-spec")
  Dir.mkdir_p(dir)
  ENV["TMPDIR"] = dir
  begin
    yield dir
  ensure
    previous ? (ENV["TMPDIR"] = previous) : ENV.delete("TMPDIR")
    FileUtils.rm_rf(dir)
  end
end

# A context whose *request* already carries a session cookie holding *values* —
# the shape a returning client's request has. Built through a detached session so
# it needs no context of its own.
def build_context_with_cookie(values : Hash(String, JSON::Any), **args) : HTTP::Server::Context
  seed = Kemal::Session.new
  values.each { |key, value| seed.store[key] = value }
  name = Kemal::Session.config.cookie_name
  build_context("#{name}=#{URI.encode_www_form(seed.encode)}", **args)
end

# A context whose session already holds *token* as the real CSRF token.
def build_csrf_context(token : String, **args) : HTTP::Server::Context
  context = build_context(**args)
  context.session.string(Kemal::Session::CSRF::SESSION_KEY, token)
  context
end

# A fresh `{real, masked}` CSRF token pair — what a client is handed alongside
# what the session must hold for it to verify. Pass *action*/*method* for a
# per-form masked token.
def csrf_token_pair(action : String? = nil, method : String? = nil) : {String, String}
  session = Kemal::Session.new
  {Kemal::Session::CSRF.real_token(session), Kemal::Session::CSRF.token(session, action, method)}
end

# The shape nearly every verification example needs: a `POST /items` carrying a
# valid masked token in `X-CSRF-Token`, whose session holds the matching real
# token. Extra *headers* (`Origin`, `Host`, forwarded headers) are merged in.
def build_csrf_post(headers : HTTP::Headers = HTTP::Headers.new, path : String = "/items",
                    body : String? = nil, content_type : String? = nil) : HTTP::Server::Context
  real, token = csrf_token_pair
  headers[Kemal::Session::CSRF::HEADER_NAME] = token
  build_csrf_context(real, method: "POST", path: path, body: body,
    content_type: content_type, headers: headers)
end

# A new request carrying the session cookie *context* just wrote — the returning
# client's next request, and the only way to assert what actually round-trips.
def reread(context : HTTP::Server::Context, **args) : HTTP::Server::Context
  name = Kemal::Session.config.cookie_name
  build_context("#{name}=#{context.response.cookies[name].value}", **args)
end

# The size Rails' `check_for_overflow!` would measure for a session: the cookie
# name plus the raw (unescaped) encrypted value.
def cookie_size(session : Kemal::Session) : Int32
  Kemal::Session.config.cookie_name.bytesize + session.encode.bytesize
end

# The longest `"a" * n` payload whose cookie still measures <= *target* bytes.
# Measured rather than hard-coded so the boundary examples stay honest if the
# envelope or the ciphertext framing ever changes size.
def payload_fitting_in(target : Int32) : String
  low, high = 0, target
  while low < high
    mid = (low + high + 1) // 2
    probe = Kemal::Session.new
    probe.store["blob"] = JSON::Any.new("a" * mid)
    cookie_size(probe) <= target ? (low = mid) : (high = mid - 1)
  end
  "a" * low
end

# Whether a Ruby with ActiveSupport is available for live cross-language checks.
ORACLE_PATH = File.expand_path("support/oracle.rb", __DIR__)

# The CSRF oracle needs actionpack (not just active_support), resolved through
# bundler/inline against the installed gems.
CSRF_ORACLE_PATH = File.expand_path("support/csrf_oracle.rb", __DIR__)

private def ruby_runs?(args : Array(String)) : Bool
  return false unless Process.find_executable("ruby")
  Process.run("ruby", args, output: Process::Redirect::Close, error: Process::Redirect::Close).success?
rescue
  false
end

# Probed once each: every check costs a Ruby process, and the answer cannot
# change while the suite runs.
ORACLE_AVAILABLE      = ruby_runs?(["-e", "require 'active_support'"])
CSRF_ORACLE_AVAILABLE = ruby_runs?([CSRF_ORACLE_PATH, "available"])

# Skips the calling example unless the oracle it needs is installed. `file`/`line`
# default at the *call site*, so the skip is reported against the example.
def require_oracle!(file = __FILE__, line = __LINE__) : Nil
  pending!("ruby + active_support not available", file, line) unless ORACLE_AVAILABLE
end

def require_csrf_oracle!(file = __FILE__, line = __LINE__) : Nil
  pending!("ruby + actionpack not available", file, line) unless CSRF_ORACLE_AVAILABLE
end

# Runs the Ruby oracles with the given args, returning stdout (stripped).
def oracle(*args : String) : String
  run_ruby(ORACLE_PATH, args.to_a)
end

def csrf_oracle(*args : String) : String
  run_ruby(CSRF_ORACLE_PATH, args.to_a)
end

# `Process.quote` is required because tokens, cookie values and JSON args are
# full of shell metacharacters. Both oracles keep stderr clean on success, so
# folding it into stdout costs nothing and makes failures self-explanatory.
private def run_ruby(script : String, args : Array(String)) : String
  output = `#{Process.quote(["ruby", script] + args)} 2>&1`
  raise "oracle failed: #{output}" unless $?.success?
  output.strip
end
