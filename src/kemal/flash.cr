module Kemal
  class Session
    # A minimal, `kemal-session`-compatible flash: string values that survive
    # exactly one subsequent read. Backed by prefixed keys in the session hash.
    #
    # NOTE: this is *not* Rails' `flash` structure (Rails stores a nested
    # `{"flash":{...}}` FlashHash). Interop with Rails flash is intentionally
    # out of scope; see the README's "complex objects" suggestions.
    class Flash
      PREFIX = "_flash_"

      def initialize(@session : Session)
      end

      # Stores a flash string.
      def []=(key : String, value : String) : String
        @session.string(prefixed(key), value)
      end

      # Reads and consumes a flash string, or `nil` if absent.
      def []?(key : String) : String?
        stored = prefixed(key)
        value = @session.string?(stored)
        @session.delete(stored) if value
        value
      end

      # Reads and consumes a flash string, raising `KeyError` if absent.
      def [](key : String) : String
        self[key]? || raise KeyError.new("Flash has no key #{key.inspect}")
      end

      private def prefixed(key : String) : String
        "#{PREFIX}#{key}"
      end
    end
  end
end
