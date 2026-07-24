require "./spec_helper"

# Live cross-language interop against a real Ruby + ActiveSupport oracle.
# Skipped automatically when Ruby/ActiveSupport isn't installed.
describe "Rails interop (live oracle)" do
  before_each { configure_session(cookie_name: "_myapp_session") }

  it "a cookie written by Crystal is decrypted by Rails/ActiveSupport" do
    require_oracle!

    s = Kemal::Session.new
    s.string("session_id", "deadbeefdeadbeefdeadbeefdeadbeef")
    s.int("user_id", 123)
    s.bool("admin", false)
    s.string("name", "Katherine")

    wire = URI.encode_www_form(s.encode)
    parsed = JSON.parse(oracle("decode", RailsFixture::SECRET, "_myapp_session", wire))
    parsed["user_id"].as_i.should eq(123)
    parsed["admin"].as_bool.should be_false
    parsed["name"].as_s.should eq("Katherine")
  end

  it "a cookie written by Rails/ActiveSupport is decrypted by Crystal" do
    require_oracle!

    # A secret other than the fixture's, so key derivation is exercised on a
    # value no checked-in expectation could be masking.
    secret = "9f" * 32
    configure_session(cookie_name: "_myapp_session", secret: secret)

    session_json = %({"session_id":"cafebabecafebabecafebabecafebabe","user_id":7,"admin":true})
    wire = oracle("encode", secret, "_myapp_session", session_json)

    enc = Kemal::Session::MessageEncryptor.from_secret(secret, RailsFixture::SALT)
    payload = enc.decrypt_and_verify(URI.decode_www_form(wire), "cookie._myapp_session")

    parsed = JSON.parse(payload)
    parsed["user_id"].as_i.should eq(7)
    parsed["admin"].as_bool.should be_true
  end
end
