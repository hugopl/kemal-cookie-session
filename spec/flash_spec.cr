require "./spec_helper"

describe Kemal::Session::Flash do
  before_each { configure_session }

  it "reads a value exactly once (read-once semantics)" do
    ctx = build_context
    flash = ctx.flash
    flash["notice"] = "Saved!"
    flash["notice"]?.should eq("Saved!")
    flash["notice"]?.should be_nil # consumed

    # `[]` raises for a key that was never set, and for one already consumed.
    expect_raises(KeyError) { flash["notice"] }
    expect_raises(KeyError) { flash["missing"] }
  end

  it "persists across requests until consumed" do
    ctx = build_context
    ctx.flash["alert"] = "Careful"
    ctx.session.commit

    reread(ctx).flash["alert"]?.should eq("Careful")
  end
end
