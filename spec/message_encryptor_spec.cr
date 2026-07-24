require "./spec_helper"

# The encryptor Rails would build for the fixture's secret. Nothing here reads
# `Session.config`, so no `configure_session` is needed.
private def encryptor : Kemal::Session::MessageEncryptor
  Kemal::Session::MessageEncryptor.from_secret(RailsFixture::SECRET, RailsFixture::SALT)
end

private def gcm_key : Bytes
  Kemal::Session::Crypto.derive_key("s", "salt")
end

describe Kemal::Session::Crypto do
  it "derives the same 32-byte key as ActiveSupport::KeyGenerator" do
    key = Kemal::Session::Crypto.derive_key(RailsFixture::SECRET, RailsFixture::SALT, 1000, 32)
    key.size.should eq(32)
    key.hexstring.should eq(RailsFixture::KEY_HEX)
  end

  it "AES-256-GCM encrypt/decrypt round-trips" do
    iv = Random::Secure.random_bytes(12)
    ct, tag = Kemal::Session::Crypto.encrypt(gcm_key, iv, "hello world".to_slice)
    tag.size.should eq(16)
    String.new(Kemal::Session::Crypto.decrypt(gcm_key, iv, ct, tag)).should eq("hello world")
  end

  # GCM rejects a zero-length IV, which is the one libcrypto refusal reachable
  # through this API without a wrong-sized key (that one is checked in Crystal).
  it "says which libcrypto call failed and why, leaving the error queue drained" do
    ex = expect_raises(Kemal::Session::Crypto::Error) do
      Kemal::Session::Crypto.encrypt(gcm_key, Bytes.empty, "hi".to_slice)
    end

    message = ex.message.not_nil!
    message.should contain("EVP_CIPHER_CTX_ctrl(GCM_SET_IVLEN, 0)")
    # `ERR_error_string`'s format, stable across OpenSSL 3.x:
    # "error:1C80006D:Provider routines::invalid iv length".
    message.should match(/error:[0-9A-Fa-f]+:/)
    # Draining matters so the next failure isn't blamed for this one.
    LibCrypto.err_get_error.should eq(0)
  end

  it "rejects a tampered ciphertext" do
    iv = Random::Secure.random_bytes(12)
    ct, tag = Kemal::Session::Crypto.encrypt(gcm_key, iv, "hello".to_slice)
    ct[0] ^= 0xFF_u8
    expect_raises(Kemal::Session::Crypto::Error) do
      Kemal::Session::Crypto.decrypt(gcm_key, iv, ct, tag)
    end
  end
end

describe Kemal::Session::MessageEncryptor do
  it "decrypts a genuine Rails 8 cookie into the original session hash" do
    raw = URI.decode_www_form(RailsFixture::COOKIE_WIRE)
    payload = encryptor.decrypt_and_verify(raw, "cookie.#{RailsFixture::COOKIE_KEY}")

    session = JSON.parse(payload)
    session["session_id"].as_s.should eq("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    session["user_id"].as_i.should eq(42)
    session["admin"].as_bool.should be_true
    session["ratio"].as_f.should eq(0.5)
    session["name"].as_s.should eq("Grace Hopper")
    session["_csrf_token"].as_s.should eq("xYzToken1234567890abcdefABCDEF+/=")
  end

  it "round-trips through the metadata envelope, in Rails' b64--b64--b64 wire format" do
    message = encryptor.encrypt_and_sign(%({"user_id":7}), "cookie._session_id")
    message.split("--").size.should eq(3)
    encryptor.decrypt_and_verify(message, "cookie._session_id").should eq(%({"user_id":7}))
  end

  it "rejects a wrong purpose" do
    message = encryptor.encrypt_and_sign(%({"a":1}), "cookie._session_id")
    expect_raises(Kemal::Session::InvalidMessage, /purpose mismatch/) do
      encryptor.decrypt_and_verify(message, "cookie._other")
    end
  end

  it "rejects a tampered cookie" do
    message = encryptor.encrypt_and_sign(%({"a":1}), "cookie._session_id")
    tampered = message.sub(message[0], message[0] == 'A' ? 'B' : 'A')
    expect_raises(Kemal::Session::InvalidMessage) do
      encryptor.decrypt_and_verify(tampered, "cookie._session_id")
    end
  end

  it "honors an embedded expiry" do
    expired = encryptor.encrypt_and_sign(%({"a":1}), "cookie._session_id", expires_at: Time.utc - 1.hour)
    expect_raises(Kemal::Session::ExpiredMessage) do
      encryptor.decrypt_and_verify(expired, "cookie._session_id")
    end
  end
end
