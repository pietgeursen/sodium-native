#include <nan.h>
#include "macros.h"

#include "../deps/libsodium/src/libsodium/include/sodium.h"
using namespace std;

//int
//crypto_scalarmult(unsigned char *q, const unsigned char *n,
//                  const unsigned char *p)
//{
//    return crypto_scalarmult_curve25519(q, n, p);
//}

class CryptoScalarMultAsync : public Nan::AsyncWorker {
  public:
    CryptoScalarMultAsync(Nan::Callback *callback, unsigned char *q, const unsigned char *n, const unsigned char *p)
      : Nan::AsyncWorker(callback), q(q), n(n), p(p) {}

    ~CryptoScalarMultAsync() {}

    void Execute () {
      int res = crypto_scalarmult(q, n, p);
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
    unsigned char * q;
    const unsigned char * n;
    const unsigned char * p;
};

