# kemal-cookie-session
#
# A cookie-store session for Kemal: the whole session lives in a single
# AES-256-GCM encrypted cookie, with nothing stored server-side (no engine, no
# GC). The public API mirrors the `kemal-session` shard (the two cannot be used
# at the same time).
#
# As a bonus, the cookie is byte-compatible with Rails 8's
# ActionDispatch::Session::CookieStore. See the README for details.
require "http"
require "json"
require "base64"
require "uri"

require "./kemal/exceptions"
require "./kemal/crypto"
require "./kemal/message_encryptor"
require "./kemal/config"
require "./kemal/session"
require "./kemal/handler"
require "./kemal/flash"
require "./kemal/csrf"
require "./kemal/ext/context"
