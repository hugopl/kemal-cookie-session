require "openssl"

# Crystal's stdlib `OpenSSL::Cipher` exposes `authenticated?` but does not
# surface the GCM auth-tag / IV-length controls we need to be byte-compatible
# with Rails. Reopen `LibCrypto` to add `EVP_CIPHER_CTX_ctrl` plus the GCM
# control constants so we can drive the EVP cipher directly (see `crypto.cr`).
lib LibCrypto
  EVP_CTRL_GCM_SET_IVLEN =  0x9
  EVP_CTRL_GCM_GET_TAG   = 0x10
  EVP_CTRL_GCM_SET_TAG   = 0x11

  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : LibC::Int, arg : LibC::Int, ptr : Void*) : LibC::Int
end
