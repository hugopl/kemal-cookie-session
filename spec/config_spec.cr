require "./spec_helper"

describe Kemal::Session::Config do
  before_each { configure_session }

  it "is configurable via the block form, and builds the purpose from the cookie name" do
    Kemal::Session.config do |c|
      c.secret = "topsecret"
      c.cookie_name = "_app_session"
      c.iterations = 2000
    end
    Kemal::Session.config.secret.should eq("topsecret")
    Kemal::Session.config.cookie_name.should eq("_app_session")
    Kemal::Session.config.iterations.should eq(2000)
    Kemal::Session.config.purpose.should eq("cookie._app_session")
  end

  it "aliases secret as secret_key_base" do
    Kemal::Session.config.secret_key_base = "abc"
    Kemal::Session.config.secret.should eq("abc")
    Kemal::Session.config.secret_key_base.should eq("abc")
  end

  it "raises SecretRequiredException when the secret is empty" do
    Kemal::Session.config.secret = ""
    expect_raises(Kemal::Session::SecretRequiredException) do
      Kemal::Session.config.encryptor
    end
  end

  it "rebuilds the encryptor when the secret changes" do
    Kemal::Session.config.secret = "one"
    first = Kemal::Session.config.encryptor
    Kemal::Session.config.encryptor.should be(first) # cached
    Kemal::Session.config.secret = "two"
    Kemal::Session.config.encryptor.should_not be(first)
  end
end
