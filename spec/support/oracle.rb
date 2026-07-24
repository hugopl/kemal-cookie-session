#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Independent Rails-compatible oracle used by the cross-language interop spec.
# It uses the REAL ActiveSupport primitives, configured exactly as
# ActionDispatch's EncryptedKeyRotatingCookieJar does, so it proves that cookies
# produced/consumed by this Crystal shard interoperate with genuine Rails.
#
# Usage:
#   oracle.rb encode <secret> <cookie_key> <session_json>  -> prints url-escaped wire cookie
#   oracle.rb decode <secret> <cookie_key> <wire>          -> prints session JSON
require "active_support"
require "active_support/message_encryptor"
require "active_support/key_generator"
require "json"
require "cgi"

SALT = "authenticated encrypted cookie"

def encryptor(secret)
  key = ActiveSupport::KeyGenerator.new(secret, iterations: 1000).generate_key(SALT, 32)
  ActiveSupport::MessageEncryptor.new(
    key, cipher: "aes-256-gcm",
    serializer: ActiveSupport::MessageEncryptor::NullSerializer
  )
end

cmd, secret, cookie_key, arg = ARGV
purpose = "cookie.#{cookie_key}"

case cmd
when "encode"
  serialized = JSON.generate(JSON.parse(arg)) # cookies_serializer = :json
  value = encryptor(secret).encrypt_and_sign(serialized, purpose: purpose)
  puts CGI.escape(value)
when "decode"
  value = CGI.unescape(arg)
  serialized = encryptor(secret).decrypt_and_verify(value, purpose: purpose)
  puts serialized
else
  abort "usage: oracle.rb encode|decode <secret> <cookie_key> <arg>"
end
