require "./spec_helper"

describe Kemal::Session do
  before_each { configure_session }

  describe "typed accessors" do
    it "stores and reads each supported type" do
      s = Kemal::Session.new
      s.int("count", 5)
      s.string("name", "Ada")
      s.float("ratio", 0.25)
      s.bool("admin", true)

      s.int("count").should eq(5)
      s.int?("count").should eq(5)
      s.string("name").should eq("Ada")
      s.string?("name").should eq("Ada")
      s.float("ratio").should eq(0.25)
      s.float?("ratio").should eq(0.25)
      s.bool("admin").should be_true
      s.bool?("admin").should be_true
    end

    it "treats a missing key as nil, or KeyError for the raising reader" do
      s = Kemal::Session.new
      s.int?("missing").should be_nil
      expect_raises(KeyError) { s.int("missing") }
    end

    it "guards types on read: a key reads back only as what it was written" do
      s = Kemal::Session.new
      s.string("x", "hello")
      s.int("n", 3)

      s.int?("x").should be_nil
      s.float?("x").should be_nil
      # An integer is deliberately not a float.
      s.float?("n").should be_nil
    end

    it "deletes a key regardless of type" do
      s = Kemal::Session.new
      s.string("x", "hi")
      s.int("n", 7)
      s.delete("x")
      s.string?("x").should be_nil
      s.int?("n").should eq(7)
    end
  end

  describe "#object" do
    it "stores and reads a JSON::Serializable object, returning it from the writer" do
      s = Kemal::Session.new
      written = Cart.new(items: ["a", "b"], total: 3.5)
      s.object("cart", written).should eq(written)

      cart = s.object("cart", as: Cart)
      cart.items.should eq(["a", "b"])
      cart.total.should eq(3.5)
    end

    it "stores and reads a collection of objects" do
      s = Kemal::Session.new
      s.object("carts", [Cart.new(items: ["a"], total: 1.0), Cart.new(items: ["b"], total: 2.0)])
      carts = s.object("carts", as: Array(Cart))
      carts.size.should eq(2)
      carts[1].items.should eq(["b"])
    end

    it "raises KeyError when absent, while object? returns nil for absent or mistyped" do
      s = Kemal::Session.new
      s.string("x", "not an object")

      expect_raises(KeyError) { s.object("missing", as: Cart) }
      s.object?("missing", as: Cart).should be_nil
      s.object?("x", as: Cart).should be_nil
    end
  end

  describe "flat, Rails-shaped layout" do
    it "writes a flat JSON hash (readable by Rails as session[:key])" do
      s = Kemal::Session.new
      s.int("user_id", 42)
      s.bool("admin", true)
      s.string("name", "Grace")
      JSON.parse(s.store.to_json).should eq(JSON.parse(%({"user_id":42,"admin":true,"name":"Grace"})))
    end
  end

  describe "#id" do
    it "generates a 32-char hex session_id and stores it under 'session_id'" do
      s = Kemal::Session.new
      id = s.id
      id.size.should eq(32)
      s.store["session_id"].as_s.should eq(id)
      s.id.should eq(id) # stable
    end
  end

  describe "cookie round-trip through a context" do
    it "writes an encrypted cookie that a fresh session reads back" do
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.string("role", "admin")
      s.object("cart", Cart.new(items: ["a", "b"], total: 9.0))
      # The full Int64 range: the width JSON integers have in the store.
      s.int("max", Int64::MAX)
      s.int("min", Int64::MIN)
      s.commit

      s2 = Kemal::Session.new(reread(ctx))
      s2.string("role").should eq("admin")
      s2.int("max").should eq(Int64::MAX)
      s2.int("min").should eq(Int64::MIN)

      cart = s2.object("cart", as: Cart)
      cart.items.should eq(["a", "b"])
      cart.total.should eq(9.0)
    end

    it "reads a genuine Rails 8 cookie via a context" do
      configure_session(cookie_name: RailsFixture::COOKIE_KEY)
      ctx = build_context("#{RailsFixture::COOKIE_KEY}=#{RailsFixture::COOKIE_WIRE}")
      s = Kemal::Session.new(ctx)
      s.int("user_id").should eq(42)
      s.string("name").should eq("Grace Hopper")
      s.bool("admin").should be_true
      s.id.should eq("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    end

    it "starts empty when the cookie is tampered with" do
      configure_session(cookie_name: RailsFixture::COOKIE_KEY)
      bad = RailsFixture::COOKIE_WIRE.sub("ncLb", "XXXX")
      ctx = build_context("#{RailsFixture::COOKIE_KEY}=#{bad}")
      s = Kemal::Session.new(ctx)
      s.store.empty?.should be_true
    end
  end

  describe "emptying the session" do
    # The client still sends the cookie it was given, so deleting the last key
    # must expire it rather than leave the stale value in place.
    it "expires the cookie when the last key is deleted" do
      ctx = build_context_with_cookie({"user_id" => JSON::Any.new(42_i64)})
      s = ctx.session
      s.delete("user_id")
      s.commit

      ctx.response.cookies["_session_id"].expired?.should be_true
    end

    it "expires the cookie when the store is emptied by any other means" do
      ctx = build_context_with_cookie({"name" => JSON::Any.new("Ada")})
      s = ctx.session
      s.store.clear
      s.save
      ctx.response.cookies["_session_id"].expired?.should be_true
    end

    it "does not set a cookie for an empty session that never had one" do
      ctx = build_context
      Kemal::Session.new(ctx).save
      ctx.response.cookies.has_key?("_session_id").should be_false
    end

    # Only reachable now that the cookie is written once, at the end: the live
    # value the intermediate `save` used to emit is never sent, so there is
    # nothing to expire and no reason to tell the client about a session it
    # never had.
    it "sets no cookie at all when a session is filled and emptied in one request" do
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.int("user_id", 42)
      s.delete("user_id")
      s.commit

      ctx.response.cookies.has_key?("_session_id").should be_false
    end
  end

  # Rails raises `ActionDispatch::Cookies::CookieOverflow` from
  # `check_for_overflow!`, which measures `name.bytesize + value.bytesize`
  # against 4096 — the *raw* encrypted value, before Rack escapes it.
  describe "cookie size limit" do
    # The setter only marks the session dirty, so the overflow surfaces from the
    # write itself — under Kemal, from `Session::Handler`'s commit.
    it "raises CookieOverflow from the commit, naming the cookie and the size" do
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.string("blob", "a" * 6144)
      ex = expect_raises(Kemal::Session::CookieOverflow) { s.commit }
      ex.message.should match(/^_session_id cookie overflowed with size \d+ bytes$/)
    end

    it "raises only once, from the write that overflowed" do
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.string("blob", "a" * 6144)
      expect_raises(Kemal::Session::CookieOverflow) { s.commit }

      # The handler commits again as it unwinds; a second raise there would
      # replace the app's error page with this one.
      s.commit
      ctx.response.cookies.has_key?("_session_id").should be_false
    end

    it "measures the raw value like Rails, accepting the largest session that fits" do
      payload = payload_fitting_in(Kemal::Session::MAX_COOKIE_SIZE)
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.string("blob", payload)
      s.commit

      cookie_size(s).should be <= Kemal::Session::MAX_COOKIE_SIZE
      # The escaped wire value is *over* the limit, so a check against the
      # cookie as written would wrongly reject this session.
      ctx.response.cookies["_session_id"].value.bytesize.should be > Kemal::Session::MAX_COOKIE_SIZE

      # One byte more than fits must be rejected.
      over = Kemal::Session.new(build_context)
      over.string("blob", payload + "a")
      expect_raises(Kemal::Session::CookieOverflow) { over.commit }
    end

    it "leaves the previously written cookie in place" do
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.int("user_id", 42)
      s.save
      good = ctx.response.cookies["_session_id"].value

      s.string("blob", "a" * 6144)
      expect_raises(Kemal::Session::CookieOverflow) { s.save }
      ctx.response.cookies["_session_id"].value.should eq(good)
    end

    it "does not raise for a detached session, which writes no cookie" do
      s = Kemal::Session.new
      s.string("blob", "a" * 6144)
      s.string("blob").size.should eq(6144)
    end
  end

  describe "#destroy and #reset" do
    # A logout only has a cookie to expire if the client sent one, which is also
    # the only shape that reaches a real logout route.
    it "destroy clears the store and expires the cookie" do
      ctx = build_context_with_cookie({"user_id" => JSON::Any.new(1_i64)})
      s = ctx.session
      s.destroy
      s.commit

      s.store.empty?.should be_true
      ctx.response.cookies["_session_id"].expired?.should be_true
    end

    it "keeps the cookie expired when the store is repopulated after destroy" do
      # The realistic shape: a logout handler that then renders a layout
      # containing `csrf_meta_tags`.
      ctx = build_context_with_cookie({"user_id" => JSON::Any.new(1_i64)})
      s = ctx.session
      s.destroy
      ctx.csrf_token
      s.string("flash", "Signed out")
      s.commit

      ctx.response.cookies["_session_id"].expired?.should be_true
      s.destroyed?.should be_true
    end

    it "still serves values in memory for the rest of the request" do
      ctx = build_context
      s = Kemal::Session.new(ctx)
      s.destroy
      s.string("name", "Ada")
      s.string("name").should eq("Ada")
    end

    it "reset lifts a previous destroy, clears the data and writes a live cookie" do
      ctx = build_context_with_cookie({"user_id" => JSON::Any.new(1_i64)})
      s = ctx.session
      old_id = s.id
      s.destroy
      s.reset
      s.commit

      s.destroyed?.should be_false
      s.int?("user_id").should be_nil
      s.id.should_not eq(old_id)

      cookie = ctx.response.cookies["_session_id"]
      cookie.expired?.should be_false
      Kemal::Session.new(reread(ctx)).id.should eq(s.id)
    end
  end
end
