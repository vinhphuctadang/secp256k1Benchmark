const crypto = require('crypto')
const elliptic = require('elliptic')
const EC = new elliptic.ec('secp256k1')
const assert = require('assert')

const chars = 'abcdefghiklmnopqrstuvwxyz0123456789'


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
  let result = ''
  for(let i = 0; i<100; i++) result += chars[parseInt(Math.random()*chars.length)]
  return result
}

async function main(){

  console.log('Preparing messages and signatures')
  let NUM_TEST = 1000
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

  let marked = Date.now()
  for(let i = 0; i<NUM_TEST; ++i) {
    let msg = msgCollection[i]
    let privKey = privateKeyCollection[i]
    let sig = sigCollection[i]
    // console.log('Signature:', sig)
    // let tmp = privKey.getPublic()
    // pubKey = tmp.x.toString('hex', 64) + tmp.y.toString('hex', 64)
    // console.log('Public key:', pubKey)
    recoveredPubKey = recoverPubKey(msg, parseSig(sig))
    // console.log('Recovered Public key:', recoveredPubKey)
    // assert.deepEqual(pubKey, recoveredPubKey)
  }

  console.log(`[Over ${NUM_TEST} test(s)] Elliptic consumed: ${Date.now() - marked} ms`)
}

main()
