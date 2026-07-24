require "openssl"
require "openssl/algorithm"
require "openssl/pkcs5"
require "./lib_crypto"

module Kemal
  class Session
    # Low-level cryptographic primitives matching Rails' defaults:
    # PBKDF2-HMAC-SHA1 key derivation and AES-256-GCM authenticated encryption.
    module Crypto
      extend self

      class Error < Exception
      end

      # Not configurable, and shouldn't be. Rails' `encrypted_cookie_cipher` can
      # technically be changed, but its only other value (`aes-256-cbc`) is a
      # different wire format there — non-AEAD ciphers get an HMAC signature
      # appended and no auth tag — so it would be a second code path, not a
      # different constant. `encrypt` also sizes its output buffer at exactly
      # `plaintext.size`, which is only correct for a stream mode like GCM.
      CIPHER_NAME  = "aes-256-gcm"
      KEY_LEN      = 32
      IV_LEN       = 12
      AUTH_TAG_LEN = 16

      # PBKDF2-HMAC-SHA1, matching `ActiveSupport::KeyGenerator`
      # (`iterations: 1000`, SHA1, 32-byte key for AES-256-GCM cookies).
      def derive_key(secret : String, salt : String, iterations : Int32 = 1000, key_len : Int32 = KEY_LEN) : Bytes
        OpenSSL::PKCS5.pbkdf2_hmac(secret, salt, iterations, OpenSSL::Algorithm::SHA1, key_len)
      end

      # Encrypts *plaintext* with AES-256-GCM. Returns `{ciphertext, auth_tag}`.
      # No additional authenticated data is used (matching Rails cookies).
      def encrypt(key : Bytes, iv : Bytes, plaintext : Bytes) : {Bytes, Bytes}
        raise ArgumentError.new("key must be #{KEY_LEN} bytes, got #{key.size}") unless key.size == KEY_LEN
        ctx = LibCrypto.evp_cipher_ctx_new
        raise Error.new("EVP_CIPHER_CTX_new failed") if ctx.null?
        begin
          check LibCrypto.evp_cipherinit_ex(ctx, cipher, nil, nil, nil, 1), "EVP_EncryptInit_ex(#{CIPHER_NAME})"
          set_ivlen(ctx, iv.size)
          check LibCrypto.evp_cipherinit_ex(ctx, nil, nil, key, iv, 1), "EVP_EncryptInit_ex(key, iv)"

          ciphertext = Bytes.new(plaintext.size)
          written = 0
          check LibCrypto.evp_cipherupdate(ctx, ciphertext, pointerof(written), plaintext, plaintext.size), "EVP_EncryptUpdate"

          extra = 0
          check LibCrypto.evp_cipherfinal_ex(ctx, ciphertext.to_unsafe + written, pointerof(extra)), "EVP_EncryptFinal_ex"
          written += extra

          tag = Bytes.new(AUTH_TAG_LEN)
          check LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN, tag.to_unsafe.as(Void*)), "EVP_CIPHER_CTX_ctrl(GCM_GET_TAG)"

          {ciphertext[0, written], tag}
        ensure
          LibCrypto.evp_cipher_ctx_free(ctx)
        end
      end

      # Decrypts and authenticates an AES-256-GCM message. Raises `Crypto::Error`
      # if the auth tag does not verify (tampering, wrong key, etc.).
      def decrypt(key : Bytes, iv : Bytes, ciphertext : Bytes, tag : Bytes) : Bytes
        raise ArgumentError.new("key must be #{KEY_LEN} bytes, got #{key.size}") unless key.size == KEY_LEN
        ctx = LibCrypto.evp_cipher_ctx_new
        raise Error.new("EVP_CIPHER_CTX_new failed") if ctx.null?
        begin
          check LibCrypto.evp_cipherinit_ex(ctx, cipher, nil, nil, nil, 0), "EVP_DecryptInit_ex(#{CIPHER_NAME})"
          set_ivlen(ctx, iv.size)
          check LibCrypto.evp_cipherinit_ex(ctx, nil, nil, key, iv, 0), "EVP_DecryptInit_ex(key, iv)"

          plaintext = Bytes.new(ciphertext.size)
          written = 0
          check LibCrypto.evp_cipherupdate(ctx, plaintext, pointerof(written), ciphertext, ciphertext.size), "EVP_DecryptUpdate"

          check LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_TAG, tag.size, tag.to_unsafe.as(Void*)), "EVP_CIPHER_CTX_ctrl(GCM_SET_TAG)"

          extra = 0
          ret = LibCrypto.evp_cipherfinal_ex(ctx, plaintext.to_unsafe + written, pointerof(extra))
          # A tag mismatch is an expected outcome (a tampered or stale cookie), so
          # it keeps its own message — but the queue still has to be drained, or
          # whatever libcrypto left there would be blamed on a later failure.
          raise Error.new("authentication failed#{error_reasons}") if ret != 1
          written += extra

          plaintext[0, written]
        ensure
          LibCrypto.evp_cipher_ctx_free(ctx)
        end
      end

      private def cipher : LibCrypto::EVP_CIPHER
        c = LibCrypto.evp_get_cipherbyname(CIPHER_NAME)
        raise Error.new("cipher #{CIPHER_NAME} not available in libcrypto") if c.null?
        c
      end

      private def set_ivlen(ctx, len : Int32) : Nil
        check LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_IVLEN, len, Pointer(Void).null),
          "EVP_CIPHER_CTX_ctrl(GCM_SET_IVLEN, #{len})"
      end

      # Fails with libcrypto's own account of what went wrong. *operation* names
      # the EVP call, since half of these are the same function driven by a
      # different control op, and the error queue supplies the reason.
      private def check(ret : LibC::Int, operation : String) : Nil
        raise Error.new("#{operation} failed#{error_reasons}") if ret != 1
      end

      # libcrypto queues an entry per error, oldest first, and keeps them until
      # read. Draining the whole queue is what makes the message complete — and
      # keeps a leftover entry from being blamed on the next operation to fail.
      private def error_reasons : String
        reasons = [] of String
        while (code = LibCrypto.err_get_error) != 0
          reasons << String.new(LibCrypto.err_error_string(code, nil))
        end
        reasons.empty? ? "" : ": #{reasons.join(", ")}"
      end
    end
  end
end
