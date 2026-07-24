require "./spec_helper"

# `xor` is private, and both of its call sites pass two `TOKEN_LENGTH` slices —
# so its size check is not reachable through the public API. Reopening the module
# is what lets the guard itself be exercised.
class Kemal::Session
  module CSRF
    def self.xor_for_spec(a : Bytes, b : Bytes) : Bytes
      xor(a, b)
    end
  end
end

describe Kemal::Session::CSRF do
  before_each { configure_session }

  describe ".real_token" do
    it "generates a Rails-shaped token, persists it and reuses it" do
      session = Kemal::Session.new
      token = Kemal::Session::CSRF.real_token(session)

      # SecureRandom.urlsafe_base64(32): 43 unpadded urlsafe base64 chars.
      token.size.should eq(43)
      token.should match(/\A[A-Za-z0-9_-]{43}\z/)
      Base64.decode(token).size.should eq(32)
      session.string(Kemal::Session::CSRF::SESSION_KEY).should eq(token)
      Kemal::Session::CSRF.real_token(session).should eq(token)
    end

    it "writes the token into the session cookie" do
      context = build_context
      Kemal::Session::CSRF.real_token(context.session)
      context.session.commit

      restored = Kemal::Session.new(reread(context))
      restored.string?(Kemal::Session::CSRF::SESSION_KEY).should_not be_nil
    end

    it "rotates after reset" do
      session = Kemal::Session.new
      first = Kemal::Session::CSRF.real_token(session)
      Kemal::Session::CSRF.reset(session)
      Kemal::Session::CSRF.real_token(session).should_not eq(first)
    end
  end

  describe ".token" do
    it "returns a masked 64-byte token that differs every call and validates" do
      session = Kemal::Session.new
      a = Kemal::Session::CSRF.token(session)
      b = Kemal::Session::CSRF.token(session)

      a.should_not eq(b)
      Base64.decode(a).size.should eq(64)
      Kemal::Session::CSRF.valid_token?(session, a).should be_true
      Kemal::Session::CSRF.valid_token?(session, b).should be_true
    end

    it "does not validate against a different session" do
      token = Kemal::Session::CSRF.token(Kemal::Session.new)
      Kemal::Session::CSRF.valid_token?(Kemal::Session.new, token).should be_false
    end
  end

  describe ".valid_token?" do
    it "accepts an unmasked (legacy) token" do
      session = Kemal::Session.new
      real = Kemal::Session::CSRF.real_token(session)
      Kemal::Session::CSRF.valid_token?(session, real).should be_true
    end

    it "accepts a per-form token only on its own path and method" do
      session = Kemal::Session.new
      token = Kemal::Session::CSRF.token(session, action: "/items", method: "post")

      Kemal::Session::CSRF.valid_token?(session, token, "/items", "POST").should be_true
      Kemal::Session::CSRF.valid_token?(session, token, "/items/", "POST").should be_true
      Kemal::Session::CSRF.valid_token?(session, token, "/other", "POST").should be_false
      Kemal::Session::CSRF.valid_token?(session, token, "/items", "PATCH").should be_false
    end

    it "accepts a global token on any path" do
      session = Kemal::Session.new
      token = Kemal::Session::CSRF.token(session)

      Kemal::Session::CSRF.valid_token?(session, token, "/items", "POST").should be_true
      Kemal::Session::CSRF.valid_token?(session, token, "/whatever", "DELETE").should be_true
    end

    it "rejects per-form tokens when per-form tokens are disabled" do
      session = Kemal::Session.new
      token = Kemal::Session::CSRF.token(session, action: "/items", method: "post")
      Kemal::Session.config.csrf_per_form_tokens = false

      Kemal::Session::CSRF.valid_token?(session, token, "/items", "POST").should be_false
    end

    it "rejects nil, empty, malformed, truncated and tampered tokens" do
      session = Kemal::Session.new
      token = Kemal::Session::CSRF.token(session)

      Kemal::Session::CSRF.valid_token?(session, nil).should be_false
      Kemal::Session::CSRF.valid_token?(session, "").should be_false
      Kemal::Session::CSRF.valid_token?(session, "not base64 at all!!").should be_false
      Kemal::Session::CSRF.valid_token?(session, token[0, 20]).should be_false
      Kemal::Session::CSRF.valid_token?(session, Base64.urlsafe_encode(Bytes.new(48), padding: false)).should be_false

      bytes = Base64.decode(token)
      bytes[40] = bytes[40] ^ 0xff
      Kemal::Session::CSRF.valid_token?(session, Base64.urlsafe_encode(bytes, padding: false)).should be_false
    end

    it "rejects everything when the session holds no token" do
      Kemal::Session::CSRF.valid_token?(Kemal::Session.new, "a" * 86).should be_false
    end
  end

  describe ".normalize_action_path" do
    it "matches Rails' normalization" do
      normalize = ->(action : String, path : String) { Kemal::Session::CSRF.normalize_action_path(action, path) }

      normalize.call("/items", "/current").should eq("/items")
      normalize.call("/items/", "/current").should eq("/items")
      normalize.call("/items?page=2", "/current").should eq("/items")
      normalize.call("https://example.com/items/", "/current").should eq("/items")
      normalize.call("new", "/items").should eq("/items/new")
      normalize.call("./new", "/items").should eq("/items/new")
    end
  end

  describe ".verified_request?" do
    it "exempts only the safe methods, and needs a token for the rest" do
      build_context(method: "GET").csrf_verified?.should be_true
      build_context(method: "HEAD").csrf_verified?.should be_true
      # Rails does not exempt OPTIONS.
      build_context(method: "OPTIONS").csrf_verified?.should be_false
      build_context(method: "POST", path: "/items").csrf_verified?.should be_false
    end

    it "accepts a token in the X-CSRF-Token header" do
      build_csrf_post.csrf_verified?.should be_true
    end

    it "accepts a token in the form body, leaving it readable for the route" do
      real, token = csrf_token_pair(action: "/items", method: "post")

      context = build_csrf_context(real,
        method: "POST", path: "/items",
        body: "authenticity_token=#{URI.encode_www_form(token)}&name=widget",
        content_type: "application/x-www-form-urlencoded",
      )
      context.csrf_verified?.should be_true
      context.params.body["name"].should eq("widget")
    end

    it "accepts a token in the query string and in a JSON body" do
      real, token = csrf_token_pair
      build_csrf_context(real, method: "POST",
        path: "/items?authenticity_token=#{URI.encode_www_form(token)}").csrf_verified?.should be_true

      real, token = csrf_token_pair
      build_csrf_context(real, method: "POST", path: "/items",
        body: %({"authenticity_token":#{token.to_json},"name":"widget"}),
        content_type: "application/json").csrf_verified?.should be_true
    end

    # Parsing a multipart body spools every file part to `Dir.tempdir`, so a
    # token found before `params` is read must never get that far.
    it "does not touch the request body when the header or query string carries the token" do
      body, content_type = multipart_upload

      with_empty_tempdir do |dir|
        build_csrf_post(body: body, content_type: content_type).csrf_verified?.should be_true
        Dir.children(dir).should be_empty

        real, token = csrf_token_pair
        build_csrf_context(real, method: "POST",
          path: "/items?authenticity_token=#{URI.encode_www_form(token)}",
          body: body, content_type: content_type).csrf_verified?.should be_true
        Dir.children(dir).should be_empty
      end
    end

    it "rejects a cross-origin or null origin request even with a valid token" do
      build_csrf_post(HTTP::Headers{
        "Host"   => "app.example.com",
        "Origin" => "https://evil.example.com",
      }).csrf_verified?.should be_false

      build_csrf_post(HTTP::Headers{"Origin" => "null"}).csrf_verified?.should be_false
    end

    it "accepts a same-origin request, honouring X-Forwarded-Proto" do
      build_csrf_post(HTTP::Headers{
        "Host"              => "app.example.com",
        "X-Forwarded-Proto" => "https",
        "Origin"            => "https://app.example.com",
      }).csrf_verified?.should be_true
    end

    it "can compare the origin against a configured base URL" do
      Kemal::Session.config.csrf_base_url = "https://app.example.com"

      build_csrf_post(HTTP::Headers{
        "Host"   => "internal-1.local:3000",
        "Origin" => "https://app.example.com",
      }).csrf_verified?.should be_true
    end

    it "trusts forwarded headers by default, as Rails does" do
      Kemal::Session.config.csrf_trust_forwarded_headers.should be_true

      build_csrf_post(HTTP::Headers{
        "Host"             => "internal-1.local:3000",
        "X-Forwarded-Host" => "app.example.com",
        "Origin"           => "http://app.example.com",
      }).csrf_verified?.should be_true
    end

    it "ignores forwarded headers when they are not trusted" do
      Kemal::Session.config.csrf_trust_forwarded_headers = false

      # The base URL is the real Host, so a spoofed forwarded host no longer
      # lets an attacker's origin match.
      build_csrf_post(HTTP::Headers{
        "Host"              => "app.example.com",
        "X-Forwarded-Proto" => "https",
        "X-Forwarded-Host"  => "evil.example.com",
        "Origin"            => "https://evil.example.com",
      }).csrf_verified?.should be_false

      build_csrf_post(HTTP::Headers{
        "Host"              => "app.example.com",
        "X-Forwarded-Proto" => "https",
        "X-Forwarded-Host"  => "evil.example.com",
        "Origin"            => "http://app.example.com",
      }).csrf_verified?.should be_true
    end

    it "can skip the origin check entirely" do
      Kemal::Session.config.csrf_origin_check = false

      build_csrf_post(HTTP::Headers{"Origin" => "https://evil.example.com"}).csrf_verified?.should be_true
    end
  end

  describe ".verify!" do
    it "is a no-op on a verified request" do
      build_csrf_post.verify_csrf!
    end

    it "says plainly when it is the token that failed" do
      ex = expect_raises(Kemal::Session::InvalidAuthenticityToken) do
        build_context(method: "POST", path: "/items").verify_csrf!
      end
      ex.message.should eq("CSRF verification failed for POST /items")
    end

    it "names both URLs when the origin is what failed" do
      ex = expect_raises(Kemal::Session::InvalidAuthenticityToken) do
        build_csrf_post(HTTP::Headers{
          "Host"   => "app.example.com",
          "Origin" => "https://app.example.com",
        }).verify_csrf!
      end

      # The realistic cause: TLS terminated at a proxy that doesn't forward the
      # scheme, so the base URL is http:// and every POST fails.
      ex.message.to_s.should contain("https://app.example.com")
      ex.message.to_s.should contain("http://app.example.com")
    end
  end

  describe Kemal::Session::CSRF::Handler do
    it "lets exempted paths through, by string and by regex, and rejects the rest" do
      handler = Kemal::Session::CSRF::Handler.new(except: ["/webhooks/stripe", /\A\/api\//])
      reached = [] of String
      handler.next = ->(ctx : HTTP::Server::Context) { reached << ctx.request.path; nil }

      handler.call(build_context(method: "POST", path: "/webhooks/stripe"))
      handler.call(build_context(method: "POST", path: "/api/items"))
      expect_raises(Kemal::Session::InvalidAuthenticityToken) do
        handler.call(build_context(method: "POST", path: "/items"))
      end

      reached.should eq(["/webhooks/stripe", "/api/items"])
    end

    it "lets the skip predicate bypass verification" do
      handler = Kemal::Session::CSRF::Handler.new
      handler.skip = ->(ctx : HTTP::Server::Context) do
        !!ctx.request.headers["Authorization"]?.try(&.starts_with?("Bearer "))
      end
      called = false
      handler.next = ->(_ctx : HTTP::Server::Context) { called = true; nil }

      handler.call(build_context(method: "POST", path: "/items",
        headers: HTTP::Headers{"Authorization" => "Bearer abc"}))
      called.should be_true

      expect_raises(Kemal::Session::InvalidAuthenticityToken) do
        handler.call(build_context(method: "POST", path: "/items"))
      end
    end

    it "cleans up spooled temp files when it rejects a multipart request" do
      body, content_type = multipart_upload
      handler = Kemal::Session::CSRF::Handler.new
      handler.next = ->(_ctx : HTTP::Server::Context) { raise "route should not be reached" }

      with_empty_tempdir do |dir|
        context = build_context(method: "POST", path: "/items",
          body: body, content_type: content_type)

        expect_raises(Kemal::Session::InvalidAuthenticityToken) { handler.call(context) }

        # Kemal cleans up in `RouteHandler#process_request`, which never runs
        # when the handler raises before `call_next`. Without the upload having
        # been spooled at all, this example would prove nothing.
        context.params.files.should_not be_empty
        Dir.children(dir).should be_empty
      end
    end

    it "calls the next handler for a verified request" do
      called = false
      handler = Kemal::Session::CSRF::Handler.new
      handler.next = ->(_ctx : HTTP::Server::Context) { called = true; nil }

      handler.call(build_csrf_post)
      called.should be_true
    end
  end

  describe "view helpers" do
    it "renders Rails-shaped meta tags" do
      context = build_context
      tags = context.csrf_meta_tags

      tags.should contain(%(<meta name="csrf-param" content="authenticity_token" />))
      tags.should match(/<meta name="csrf-token" content="([A-Za-z0-9_-]{86})" \/>/)

      token = tags.match(/content="([A-Za-z0-9_-]{86})"/).not_nil![1]
      Kemal::Session::CSRF.valid_token?(context.session, token).should be_true
    end

    it "renders a hidden field bound to the form's action" do
      context = build_context
      field = context.csrf_hidden_field("/items", "post")

      field.should contain(%(name="authenticity_token"))
      field.should contain(%(autocomplete="off"))

      token = field.match(/value="([A-Za-z0-9_-]+)"/).not_nil![1]
      Kemal::Session::CSRF.valid_token?(context.session, token, "/items", "POST").should be_true
      Kemal::Session::CSRF.valid_token?(context.session, token, "/other", "POST").should be_false
    end
  end

  describe "token masking" do
    it "names the operands when they differ in size" do
      pad = Bytes.new(Kemal::Session::CSRF::TOKEN_LENGTH, 0xAA_u8)

      # A short first operand used to fall off the end of `a` with a bare
      # `IndexError` raised from inside the masking routine.
      expect_raises(ArgumentError, "xor operands must be the same size, got 31 and 32") do
        Kemal::Session::CSRF.xor_for_spec(pad[0, 31], Bytes.new(32))
      end

      # The dangerous direction: `out` was sized from `b`, so a longer pad was
      # silently truncated and the result masked with only part of it.
      expect_raises(ArgumentError, "xor operands must be the same size, got 32 and 31") do
        Kemal::Session::CSRF.xor_for_spec(pad, Bytes.new(31))
      end
    end
  end
end
