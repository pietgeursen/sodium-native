#include <nan.h>
#include "macros.h"

#include "../deps/libsodium/src/libsodium/include/sodium.h"

class CryptoSecretBoxEasyAsync : public Nan::AsyncWorker {
 public:
  CryptoSecretBoxEasyAsync(Nan::Callback *callback, unsigned char *cipher, const unsigned char *message, unsigned long long ciphertext_length, const unsigned char *nonce,
                      const unsigned char *key)
    : Nan::AsyncWorker(callback), cipher(cipher), message(message), ciphertext_length(ciphertext_length), nonce(nonce), key(key)  {}
  ~CryptoSecretBoxEasyAsync() {}

  void Execute () {
    crypto_secretbox_easy((unsigned char *) message, cipher, ciphertext_length, (unsigned char *) nonce, (unsigned char *) key);
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
 unsigned char *cipher;
 const unsigned char *message;
 unsigned long long ciphertext_length;
 const unsigned char *nonce;
 const unsigned char *key;
};
