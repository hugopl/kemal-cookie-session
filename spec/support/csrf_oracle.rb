#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Independent CSRF oracle used by the cross-language interop spec. It drives the
# REAL ActionController::RequestForgeryProtection implementation, so it proves
# that authenticity tokens produced/consumed by this Crystal shard interoperate
# with genuine Rails rather than with our reading of it.
#
# Usage:
#   csrf_oracle.rb available
#     -> prints the actionpack version
#   csrf_oracle.rb mask <real_token> [action] [method]
#     -> prints a masked token (per-form when action+method are given)
#   csrf_oracle.rb valid <real_token> <masked_token> <request_path> <request_method>
#     -> prints "true" or "false"
#
# Gems are resolved against what is already installed (no network, no install).
require "bundler/inline"
gemfile(false) do
  source "https://rubygems.org"
  gem "actionpack"
end

require "action_controller"
require "action_dispatch/testing/test_request"
require "active_support/core_ext/hash/indifferent_access"
require "securerandom"

class OracleController < ActionController::Base
  # Matches Rails' own `load_defaults 5.2`+ behaviour and this shard's
  # `config.csrf_per_form_tokens` default.
  self.per_form_csrf_tokens = true
  self.allow_forgery_protection = true
end

# Builds a controller bound to a request for *path*/*method* whose session holds
# *real_token* under `_csrf_token`, the way ActionDispatch's SessionStore strategy
# expects to find it.
def controller_for(real_token, path, method)
  request = ActionDispatch::TestRequest.create
  request.request_method = method
  request.path = path
  request.session = ActiveSupport::HashWithIndifferentAccess.new("_csrf_token" => real_token)

  controller = OracleController.new
  controller.set_request!(request)
  controller.set_response!(OracleController.make_response!(request))
  controller
end

cmd, *rest = ARGV

case cmd
when "available"
  puts ActionPack::VERSION::STRING
when "mask"
  real_token, action, method = rest
  form_options = action && method ? { action: action, method: method } : {}
  controller = controller_for(real_token, action || "/", "GET")
  puts controller.send(:masked_authenticity_token, form_options: form_options)
when "valid"
  real_token, masked_token, path, method = rest
  controller = controller_for(real_token, path, method)
  puts controller.send(:valid_authenticity_token?, nil, masked_token)
else
  abort "usage: csrf_oracle.rb available|mask|valid ..."
end
