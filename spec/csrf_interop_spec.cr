require "./spec_helper"

# Live cross-language CSRF interop against real ActionController.
# Skipped automatically when Ruby/actionpack isn't installed.
describe "CSRF interop (live oracle)" do
  before_each { configure_session(cookie_name: "_myapp_session") }

  it "a global and an unmasked token minted by Crystal are accepted by Rails" do
    require_csrf_oracle!

    real, token = csrf_token_pair
    csrf_oracle("valid", real, token, "/items", "POST").should eq("true")
    # Rails still accepts the bare real token (the pre-4.1 shape).
    csrf_oracle("valid", real, real, "/items", "POST").should eq("true")
  end

  it "a per-form token minted by Crystal is accepted by Rails on its own route only" do
    require_csrf_oracle!

    real, token = csrf_token_pair(action: "/items", method: "post")

    csrf_oracle("valid", real, token, "/items", "POST").should eq("true")
    csrf_oracle("valid", real, token, "/other", "POST").should eq("false")
    csrf_oracle("valid", real, token, "/items", "PATCH").should eq("false")
  end

  it "a global token minted by Rails is accepted by Crystal" do
    require_csrf_oracle!

    session = Kemal::Session.new
    real = Kemal::Session::CSRF.real_token(session)
    token = csrf_oracle("mask", real)

    Kemal::Session::CSRF.valid_token?(session, token, "/items", "POST").should be_true
  end

  it "a per-form token minted by Rails is accepted by Crystal on its own route only" do
    require_csrf_oracle!

    session = Kemal::Session.new
    real = Kemal::Session::CSRF.real_token(session)
    token = csrf_oracle("mask", real, "/items", "post")

    Kemal::Session::CSRF.valid_token?(session, token, "/items", "POST").should be_true
    Kemal::Session::CSRF.valid_token?(session, token, "/other", "POST").should be_false
    Kemal::Session::CSRF.valid_token?(session, token, "/items", "PATCH").should be_false
  end

  it "a token from Rails travelling in a Rails-written session cookie verifies a Kemal POST" do
    require_csrf_oracle!
    require_oracle!

    # Rails signs a user in, storing its CSRF token in the session cookie...
    real = Kemal::Session::CSRF.real_token(Kemal::Session.new)
    session_json = %({"session_id":"cafebabecafebabecafebabecafebabe","_csrf_token":"#{real}","user_id":7})
    wire = oracle("encode", RailsFixture::SECRET, "_myapp_session", session_json)

    # ...and renders a form whose token is masked by real ActionController.
    token = csrf_oracle("mask", real, "/items", "post")

    # The browser then posts that form to a Kemal route.
    context = build_context(
      cookie_header: "_myapp_session=#{wire}",
      method: "POST", path: "/items",
      body: "authenticity_token=#{URI.encode_www_form(token)}&name=widget",
      content_type: "application/x-www-form-urlencoded",
    )

    context.session.int("user_id").should eq(7)
    context.csrf_verified?.should be_true
  end

  it "a Kemal-issued token survives the round trip through a Rails-read cookie" do
    require_csrf_oracle!
    require_oracle!

    # Kemal mints the token and writes the session cookie...
    context = build_context
    token = context.csrf_token
    context.session.commit
    wire = context.response.cookies["_myapp_session"].value

    # ...Rails reads the cookie and validates the token against it.
    real = JSON.parse(oracle("decode", RailsFixture::SECRET, "_myapp_session", wire))["_csrf_token"].as_s
    csrf_oracle("valid", real, token, "/items", "POST").should eq("true")
  end
end
