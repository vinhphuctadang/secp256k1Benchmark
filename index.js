const crypto = require('crypto')
const elliptic = require('elliptic')
const secp256k1 = require('secp256k1')
const EC = new elliptic.ec('secp256k1')
const assert = require('assert')

function hash(data){
  return crypto.createHash('sha256').update(data).digest('hex')
}

function hexToDecimal(x){
  return EC.keyFromPrivate(x, "hex").getPrivate().toString(10);
}

function parseSig(sig){
  let buffer = Buffer.from(sig,'base64')
  let r = buffer.slice(0,32)
  let s = buffer.slice(32,64)
  let recoveryParam = buffer[64]
  return {r: r, s: s, recoveryParam: recoveryParam}
}

function recoverPubKey(data,signature){
  let dataHash = hash(data)
  // console.log(signature.recoveryParam)
  let pubKey = EC.recoverPubKey(
    hexToDecimal(dataHash),
    signature,
    signature.recoveryParam,
    "hex"
  )
  return pubKey.x.toString('hex', 64) + pubKey.y.toString('hex', 64)
}

function generatePrivateKey(){
  let key = EC.genKeyPair()
  return key
}

function generateMessage(){
  return crypto.randomBytes(100)
}

let NUM_TEST = 10
let msgCollection = []
let sigCollection = []
let privateKeyCollection = []

for(let i = 0; i<NUM_TEST; i++) {
  let privKey = generatePrivateKey()
  let msg = generateMessage()
  let sig = privKey.sign(hash(msg))
  sig = Buffer.concat([sig.r.toBuffer('be',32), sig.s.toBuffer('be', 32), Buffer.from([sig.recoveryParam])]).toString('base64')

  privateKeyCollection.push(privKey)
  sigCollection.push(sig)
  msgCollection.push(msg)
}

function main(){
  console.log('Preparing messages and signatures')
  let marked = Date.now()
  for(let i = 0; i<NUM_TEST; ++i) {
    let msgHash = msgCollection[i]
    let privKey = privateKeyCollection[i]
    let sig = parseSig(sigCollection[i])

    recoveredPubKey = recoverPubKey(msg, sig)
    // console.log(recoveredPubKey)
  }

  console.log(`[Over ${NUM_TEST} test(s)] Elliptic consumed: ${Date.now() - marked} ms`)
}

function test(){
  console.log(msgCollection[0].toString('hex'))
  // recover public key of secp256k1-node lib
  let msgHash = new Uint8Array(Buffer.from(hash(msgCollection[0]), 'hex'))
  let privKey = privateKeyCollection[0]
  let sig = parseSig(sigCollection[0])

  let mainSig = new Uint8Array(Buffer.concat([sig.r, sig.s]))

  console.log('==>',Buffer.from(msgHash).toString('hex'), sig.recoveryParam)

  // console.log(mainSig)
  let recoveredPubKey = secp256k1.ecdsaRecover(mainSig, sig.recoveryParam, msgHash, false)
  console.log(Buffer.from(recoveredPubKey).toString('hex').substring(2)) // 0x04 as prefix
  // console.log(recoveredPubKey)

  console.log('Hash:',hash(msgCollection[0]).length)
  recoveredPubKey = recoverPubKey(msgCollection[0], sig)
  console.log(recoveredPubKey)
}

// main()
test()
