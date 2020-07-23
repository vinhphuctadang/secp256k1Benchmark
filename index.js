const crypto = require('crypto')
const elliptic = require('elliptic')
const secp256k1_node = require('secp256k1') // from secp256k1-node
const EC = new elliptic.ec('secp256k1')
const assert = require('assert')
const { instantiateSecp256k1 } = require('@bitauth/libauth') // bitcoin-ts deprecated

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

function generatePrivateKey(){
  let key = EC.genKeyPair()
  return key
}

function generateMessage(){
  return crypto.randomBytes(100)
}

// prepare data
let NUM_TEST = 5000

let msgCollection = []
let sigCollection = []
let privateKeyCollection = []
let publicKeyCollection = []

function init(){
  for(let i = 0; i<NUM_TEST; i++) {
    let privKey = generatePrivateKey()
    let msg = generateMessage()
    let sig = privKey.sign(hash(msg))
    sig = Buffer.concat([sig.r.toBuffer('be',32), sig.s.toBuffer('be', 32), Buffer.from([sig.recoveryParam])]).toString('base64')

    privateKeyCollection.push(privKey)
    sigCollection.push(sig)
    msgCollection.push(msg)
  }
}

function test_elliptic(){

  let totalTime = 0
  for(let i = 0; i<NUM_TEST; ++i) {

    let marked = Date.now()
    let msg = msgCollection[i]
    let signature = parseSig(sigCollection[i])
    let msgHash = hash(msg)

    let pubKey = EC.recoverPubKey(
      hexToDecimal(msgHash),
      signature,
      signature.recoveryParam,
      "hex"
    )

    // output
    let recoveredPubKey = pubKey.x.toString('hex', 64) + pubKey.y.toString('hex', 64)

    // time measure
    totalTime += Date.now() - marked

    // console.log(recoveredPubKey)

    // save public key for making comparison to other packages
    publicKeyCollection.push(recoveredPubKey)
  }
  console.log(`[Over ${NUM_TEST} public key recover cases] Elliptic finished after: ${totalTime} ms`)
}

function test_secpk256k1node(){

  let totalTime = 0
  for(let i = 0; i<NUM_TEST; ++i) {

    let marked = Date.now()

    let msgHash = new Uint8Array(Buffer.from(hash(msgCollection[i]), 'hex'))
    let sigBuffer = Buffer.from(sigCollection[i], 'base64')
    let signature = new Uint8Array(sigBuffer.slice(0,64))
    let recoveryParam = sigBuffer[64]

    // output
    let tmp = secp256k1_node.ecdsaRecover(signature, recoveryParam, msgHash, false)
    let recoveredPubKey = Buffer.from(tmp).toString('hex').substring(2)
    // time measure
    totalTime += Date.now() - marked

    // compare
    assert.equal(publicKeyCollection[i], recoveredPubKey)
  }
  console.log(`[Over ${NUM_TEST} public key recover cases] secp256k1-node finished after: ${totalTime} ms`)
}

async function test_libauth(){

  const secp256k1_libauth = await instantiateSecp256k1()
  let totalTime = 0

  for(let i = 0; i<NUM_TEST; ++i) {
    let marked = Date.now()

    let msgHash = new Uint8Array(Buffer.from(hash(msgCollection[i]), 'hex'))
    let sigBuffer = Buffer.from(sigCollection[i], 'base64')
    let signature = new Uint8Array(sigBuffer.slice(0,64))
    let recoveryParam = sigBuffer[64]

    // output
    let tmp = secp256k1_libauth.recoverPublicKeyUncompressed(signature, recoveryParam, msgHash)
    let recoveredPubKey = Buffer.from(tmp).toString('hex').substring(2) // 0x04 as prefix

    // time measure
    totalTime += Date.now() - marked

    // compare
    assert.equal(publicKeyCollection[i], recoveredPubKey)
  }
  console.log(`[Over ${NUM_TEST} public key recover cases] libauth finished after: ${totalTime} ms`)
}

async function main(){
  console.log(`Initializing ${NUM_TEST} random private keys, messages and signatures (signatures are signed by elliptic)...`)
  init()
  console.log('Benchmarking elliptic')
  test_elliptic()
  console.log('Benchmarking secpk256k1node')
  test_secpk256k1node()
  console.log('Benchmarking libauth')
  await test_libauth()

}

main()
