require "base64"
require "json"
require "random/secure"

module Kemal
  class Session
    # Reimplements the subset of `ActiveSupport::MessageEncryptor` that Rails'
    # encrypted cookie jar uses, byte-for-byte compatibly:
    #
    # * AES-256-GCM, output as `strict_base64(ciphertext)--strict_base64(iv)--strict_base64(tag)`
    # * the "legacy" metadata envelope `{"_rails":{"message":<b64>,"exp":<iso8601|null>,"pur":<purpose>}}`
    #
    # Note: values here are the *raw* cookie strings (standard base64). URL/CGI
    # escaping of the cookie value on the wire is handled by `Kemal::Session`.
    class MessageEncryptor
      SEPARATOR = "--"

      getter key : Bytes

      def initialize(@key : Bytes)
        raise ArgumentError.new("key must be #{Crypto::KEY_LEN} bytes") unless @key.size == Crypto::KEY_LEN
      end

      # Derives the key from a secret exactly like Rails does for cookies.
      def self.from_secret(secret : String, salt : String, iterations : Int32 = 1000) : MessageEncryptor
        new(Crypto.derive_key(secret, salt, iterations))
      end

      # --- Rails "encrypt_and_sign" / "decrypt_and_verify" (with metadata) ---

      # Wraps *payload* in the legacy metadata envelope and encrypts it.
      def encrypt_and_sign(payload : String, purpose : String, expires_at : Time? = nil) : String
        envelope = {
          "_rails" => {
            "message" => Base64.strict_encode(payload),
            "exp"     => expires_at.try(&.to_utc.to_rfc3339(fraction_digits: 3)),
            "pur"     => purpose,
          },
        }
        encrypt_bytes(envelope.to_json.to_slice)
      end

      # Decrypts *message*, verifies its purpose and expiry, and returns the
      # inner payload string. Raises `InvalidMessage` / `ExpiredMessage`.
      def decrypt_and_verify(message : String, purpose : String) : String
        plaintext = String.new(decrypt_bytes(message))

        envelope = JSON.parse(plaintext)
        rails = envelope["_rails"]?
        raise InvalidMessage.new("missing _rails metadata envelope") unless rails

        pur = rails["pur"]?.try(&.as_s?)
        unless pur == purpose
          raise InvalidMessage.new("purpose mismatch: expected #{purpose.inspect}, got #{pur.inspect}")
        end

        if exp = rails["exp"]?.try(&.as_s?)
          expires_at = Time.parse_rfc3339(exp)
          raise ExpiredMessage.new("message expired at #{exp}") if Time.utc >= expires_at
        end

        message_b64 = rails["message"]?.try(&.as_s?)
        raise InvalidMessage.new("missing message in envelope") unless message_b64
        String.new(Base64.decode(message_b64))
      rescue ex : JSON::ParseException
        raise InvalidMessage.new("payload is not valid JSON: #{ex.message}")
      end

      # --- Raw AES-256-GCM (no metadata) ---

      # Encrypts raw bytes, returning `b64(ciphertext)--b64(iv)--b64(tag)`.
      def encrypt_bytes(plaintext : Bytes) : String
        iv = Random::Secure.random_bytes(Crypto::IV_LEN)
        ciphertext, tag = Crypto.encrypt(@key, iv, plaintext)
        String.build do |io|
          io << Base64.strict_encode(ciphertext) << SEPARATOR
          io << Base64.strict_encode(iv) << SEPARATOR
          io << Base64.strict_encode(tag)
        end
      end

      # Decrypts a raw `b64--b64--b64` message. Raises `InvalidMessage` on any
      # structural or authentication failure.
      def decrypt_bytes(message : String) : Bytes
        parts = message.split(SEPARATOR)
        raise InvalidMessage.new("expected 3 parts, got #{parts.size}") unless parts.size == 3

        ciphertext = decode64(parts[0])
        iv = decode64(parts[1])
        tag = decode64(parts[2])

        raise InvalidMessage.new("unexpected iv length #{iv.size}") unless iv.size == Crypto::IV_LEN
        raise InvalidMessage.new("unexpected auth tag length #{tag.size}") unless tag.size == Crypto::AUTH_TAG_LEN

        Crypto.decrypt(@key, iv, ciphertext, tag)
      rescue ex : Crypto::Error
        raise InvalidMessage.new(ex.message)
      end

      private def decode64(str : String) : Bytes
        Base64.decode(str)
      rescue ex
        raise InvalidMessage.new("invalid base64 segment")
      end
    end
  end
end
