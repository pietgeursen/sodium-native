var tape = require('tape')
var alloc = require('buffer-alloc')
var sodium = require('../')


tape('crypto_scalarmult_async', function (t) {
  var peer1 = keyPair()
  var peer2 = keyPair()

  t.notEqual(peer1.secretKey, peer2.secretKey, 'diff secret keys')
  t.notEqual(peer1.publicKey, peer2.publicKey, 'diff public keys')

  var shared1 = alloc(sodium.crypto_scalarmult_BYTES)
  var shared2 = alloc(sodium.crypto_scalarmult_BYTES)

  sodium.crypto_scalarmult_async(shared1, peer1.secretKey, peer2.publicKey, (err, res) => {
    sodium.crypto_scalarmult_async(shared2, peer2.secretKey, peer1.publicKey, (err, res) => {
      t.same(shared1, shared2, 'same shared secret')
      t.end()
    })
  })
})

function keyPair () {
  var secretKey = alloc(sodium.crypto_scalarmult_SCALARBYTES)
  sodium.randombytes_buf(secretKey)

  var publicKey = alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult_base(publicKey, secretKey)

  return {
    publicKey: publicKey,
    secretKey: secretKey
  }
}

