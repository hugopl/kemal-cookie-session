require "openssl"

# Crystal's stdlib (>= 1.22) already binds `EVP_CIPHER_CTX_ctrl` and the GCM
# get/set-tag constants, but not the IV-length control we need to be
# byte-compatible with Rails (12-byte IV). Reopen `LibCrypto` to add it so we
# can drive the EVP cipher directly (see `crypto.cr`).
lib LibCrypto
  EVP_CTRL_GCM_SET_IVLEN = 0x9
end
