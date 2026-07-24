require "./spec_helper"

# A context whose response writes into the returned `IO`, so a spec can inspect
# the actual bytes sent to the client — headers included. `build_context` hides
# its `IO`, and the whole point of the handler is *when* the `Set-Cookie` header
# is written relative to the body.
private def build_wired_context(cookie_header : String? = nil) : {HTTP::Server::Context, IO::Memory}
  io = IO::Memory.new
  headers = HTTP::Headers.new
  headers["Cookie"] = cookie_header if cookie_header
  request = HTTP::Request.new("GET", "/", headers)
  context = HTTP::Server::Context.new(request, HTTP::Server::Response.new(io))
  {context, io}
end

# Larger than the 8 KB output buffer, so writing it flushes the headers to the
# socket mid-route — the case an end-of-request commit loses.
private BIG_BODY = "x" * 10_000

describe Kemal::Session::Handler do
  before_each { configure_session }

  it "writes no cookie until the request is committed, then round-trips it" do
    context, _ = build_wired_context

    through_session_handler(context) do |env|
      env.session.int("user_id", 99)
      env.session.string("role", "admin")
      # Mutations are in memory only: nothing has been encrypted yet.
      env.session.dirty?.should be_true
      env.response.cookies.has_key?("_session_id").should be_false
    end

    context.session.dirty?.should be_false
    context.response.cookies["_session_id"].expired?.should be_false

    restored = Kemal::Session.new(reread(context))
    restored.int("user_id").should eq(99)
    restored.string("role").should eq("admin")
  end

  it "commits before the first byte of the body reaches the response" do
    context, _ = build_wired_context

    through_session_handler(context) do |env|
      env.session.int("user_id", 1)
      env.response.print "hello"
      # The guard ran on that write, while the header can still change.
      env.response.cookies.has_key?("_session_id").should be_true
    end
  end

  # The regression this handler exists to avoid: committing after the route
  # returns would put the cookie on a response whose headers are already gone.
  it "sends the cookie for a response larger than the output buffer" do
    context, io = build_wired_context

    through_session_handler(context) do |env|
      env.session.int("user_id", 1)
      env.response.print BIG_BODY
    end
    context.response.close

    wire = io.to_s
    wire.should contain("Set-Cookie: _session_id=")
    wire.should contain(BIG_BODY)
  end

  it "commits a response that never writes a body" do
    context, _ = build_wired_context

    through_session_handler(context) do |env|
      env.session.int("user_id", 1)
      env.response.status = :no_content
    end

    context.response.cookies.has_key?("_session_id").should be_true
  end

  it "commits when the route raises, so the mutation is not lost" do
    context, _ = build_wired_context

    expect_raises(Exception, "boom") do
      through_session_handler(context) do |env|
        env.session.int("user_id", 1)
        raise "boom"
      end
    end

    context.response.cookies.has_key?("_session_id").should be_true
  end

  it "builds no session for a request that never asks for one" do
    context, _ = build_wired_context("_session_id=#{URI.encode_www_form(Kemal::Session.new.encode)}")

    through_session_handler(context) { |env| env.response.print "no session here" }

    # Committing must not be a reason to decrypt an incoming cookie.
    context.session?.should be_nil
  end

  describe "mutations the cookie could not carry" do
    it "raises HandlerRequired when the handler is not in the chain" do
      context = build_context
      context.session_deferred = false

      ex = expect_raises(Kemal::Session::HandlerRequired) { context.session.int("user_id", 1) }
      ex.message.to_s.should contain("Kemal::Session::Handler")
    end

    it "does not require the handler for a detached session" do
      session = Kemal::Session.new
      session.int("user_id", 1)
      session.int("user_id").should eq(1)
    end

    it "raises ResponseAlreadySent when the session is mutated after the body starts" do
      context, _ = build_wired_context

      through_session_handler(context) do |env|
        env.response.print "already gone"
        expect_raises(Kemal::Session::ResponseAlreadySent) { env.session.int("user_id", 1) }
      end
    end

    it "reports an oversized session from the commit" do
      context, _ = build_wired_context

      expect_raises(Kemal::Session::CookieOverflow) do
        through_session_handler(context) { |env| env.session.string("blob", "a" * 6144) }
      end
    end
  end
end
