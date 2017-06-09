var tape = require('tape')
var sodium = require('../')
var alloc = require('buffer-alloc')

tape('crypto_secretbox_easy', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  t.throws(function () {
    sodium.crypto_secretbox_easy(alloc(0), message, nonce, key)
  }, 'throws if output is too small')

  t.throws(function () {
    sodium.crypto_secretbox_easy(alloc(message.length), message, nonce, key)
  }, 'throws if output is too small')

  sodium.crypto_secretbox_easy(output, message, nonce, key)
  t.notEqual(output, alloc(output.length))

  var result = alloc(output.length - sodium.crypto_secretbox_MACBYTES)
  t.notOk(sodium.crypto_secretbox_open_easy(result, output, alloc(sodium.crypto_secretbox_NONCEBYTES), key), 'could not decrypt')
  t.ok(sodium.crypto_secretbox_open_easy(result, output, nonce, key), 'could decrypt')

  t.same(result, message, 'decrypted message is correct')

  t.end()
})

tape('crypto_secretbox_easy async', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  t.throws(function () {
    sodium.crypto_secretbox_easy_async(alloc(0), message, nonce, key, t.fail)
  }, 'throws if output is too small')

  t.throws(function () {
    sodium.crypto_secretbox_easy_async(alloc(message.length), message, nonce, key, t.fail)
  }, 'throws if output is too small')

  sodium.crypto_secretbox_easy_async(output, message, nonce, key, (err, res) => {
    t.error(err)
    t.notEqual(output, alloc(output.length))

    var result = alloc(output.length - sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_open_easy_async(result, output, alloc(sodium.crypto_secretbox_NONCEBYTES), key, (err, ok) => {
      t.error(err)
      t.notOk(ok, 'could not decrypt')
    })

    var result1 = alloc(output.length - sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_open_easy_async(result1, output, nonce, key, (err, ok) => {
      t.error(err)
      t.ok(ok, 'could decrypt')
      t.same(result1, message, 'decrypted message is correct')
      t.end()
    })
  })
})
tape('crypto_secretbox_easy overwrite buffer', function (t) {
  var output = alloc(Buffer.byteLength('Hej, Verden!') + sodium.crypto_secretbox_MACBYTES)
  output.write('Hej, Verden!', sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_easy(output, output.slice(sodium.crypto_secretbox_MACBYTES), nonce, key)
  t.notEqual(output, alloc(output.length))

  t.ok(sodium.crypto_secretbox_open_easy(output.slice(sodium.crypto_secretbox_MACBYTES), output, nonce, key), 'could decrypt')
  t.same(output.slice(sodium.crypto_secretbox_MACBYTES), new Buffer('Hej, Verden!'), 'decrypted message is correct')

  t.end()
})

tape('crypto_secretbox_detached', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length)
  var mac = alloc(sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_detached(output, mac, message, nonce, key)

  t.notEqual(mac, alloc(mac.length), 'mac not blank')
  t.notEqual(output, alloc(output.length), 'output not blank')

  var result = alloc(output.length)

  t.notOk(sodium.crypto_secretbox_open_detached(result, output, mac, nonce, alloc(key.length)), 'could not decrypt')
  t.ok(sodium.crypto_secretbox_open_detached(result, output, mac, nonce, key), 'could decrypt')

  t.same(result, message, 'decrypted message is correct')

  t.end()
})
tape('crypto_secretbox_easy time for 10000', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  var start = Date.now(), i = 0, end = Date.now()

  for (var i = 10000; i > 0; i--) {
    sodium.crypto_secretbox_easy(output, message, nonce, key)
  }
  end = Date.now()
  var time = ((end-start)/1000)
  t.comment(`1000 boxes in ${time}s`)

  t.end()
})

tape('crypto_secretbox_easy_open time for 10000', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_easy(output, message, nonce, key)
  var result = alloc(output.length - sodium.crypto_secretbox_MACBYTES)

  var start = Date.now(), i = 0, end = Date.now()

  for (var i = 10000; i > 0; i--) {
    sodium.crypto_secretbox_open_easy(result, output, nonce, key)
  }
  end = Date.now()
  var time = ((end-start)/1000)
  t.comment(`1000 boxes in ${time}s`)

  t.end()
})

tape('crypto_secretbox_easy_async time for 10000', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)


  var start = Date.now(), i = 0, k = 0, end = Date.now()
  var logIfDone = (err, res) => {
    k++
    if(k >= 10000){
      end = Date.now()
      var time = ((end-start)/1000)
      t.comment(`1000 boxes in ${time}s`)
      t.end()
    }
  }

  for (var i = 10000; i > 0; i--) {
    sodium.crypto_secretbox_easy_async(output, message, nonce, key, logIfDone ) 
  }
})
tape('crypto_secretbox_easy_open_async time for 10000', function (t) {
  var message = new Buffer('Hej, Verden!')
  var output = alloc(message.length + sodium.crypto_secretbox_MACBYTES)

  var key = alloc(sodium.crypto_secretbox_KEYBYTES)
  sodium.randombytes_buf(key)

  var nonce = alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_easy(output, message, nonce, key)
  var result = alloc(output.length - sodium.crypto_secretbox_MACBYTES)

  var start = Date.now(), i = 0, k = 0, end = Date.now()
  var logIfDone = (err, res) => {
    k++
    if(k >= 10000){
      end = Date.now()
      var time = ((end-start)/1000)
      t.comment(`1000 boxes in ${time}s`)
      t.end()
    }
  }
  for (var i = 10000; i > 0; i--) {
    sodium.crypto_secretbox_open_easy_async(result, output, nonce, key, logIfDone)
  }
})
