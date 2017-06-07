#include <nan.h>
#include "macros.h"

#include "../deps/libsodium/src/libsodium/include/sodium.h"
using namespace std;


class CryptoSecretBoxOpenEasyAsync : public Nan::AsyncWorker {
 public:
  CryptoSecretBoxOpenEasyAsync(Nan::Callback *callback, const unsigned char *cipher, unsigned char *message, unsigned long long ciphertext_length, const unsigned char *nonce,
                      const unsigned char *key)
    : Nan::AsyncWorker(callback), cipher(cipher), message(message), ciphertext_length(ciphertext_length), nonce(nonce), key(key)  {}

  ~CryptoSecretBoxOpenEasyAsync() {}

  void Execute () {
    int res = crypto_secretbox_open_easy(message, cipher, ciphertext_length, nonce, key);
    ok = res == 0;
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
      Nan::Null(),
      ((ok == true) ? Nan::True() : Nan::False())
    };

    callback->Call(2, argv);
  }

  void HandleErrorCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
        Nan::Error(ErrorMessage())
    };

    callback->Call(1, argv);
  }

 private:
  bool ok;
  unsigned char *message;
  const unsigned char *cipher;
  unsigned long long ciphertext_length;
  const unsigned char *nonce;
  const unsigned char *key;
};
