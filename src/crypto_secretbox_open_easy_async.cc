#include <nan.h>
#include "macros.h"

#include "../deps/libsodium/src/libsodium/include/sodium.h"


class CryptoSecretBoxOpenEasyAsync : public Nan::AsyncWorker {
 public:
  CryptoSecretBoxOpenEasyAsync(Nan::Callback *callback, const unsigned char *cipher, unsigned char *message, unsigned long long ciphertext_length, const unsigned char *nonce,
                      const unsigned char *key)
    : Nan::AsyncWorker(callback), cipher(cipher), message(message), ciphertext_length(ciphertext_length), nonce(nonce), key(key)  {}

  ~CryptoSecretBoxOpenEasyAsync() {}

  void Execute () {
    crypto_secretbox_open_easy(message, cipher, ciphertext_length, nonce, key);
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Null()
    };

    callback->Call(1, argv);
  }

  void HandleErrorCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Error(ErrorMessage())
    };

    callback->Call(1, argv);
  }

 private:
 unsigned char *message;
 const unsigned char *cipher;
 unsigned long long ciphertext_length;
 const unsigned char *nonce;
 const unsigned char *key;
};
