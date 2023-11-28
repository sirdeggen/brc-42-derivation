import { PrivKey, PubKey, Hash, Bn, Point, Script } from 'bsv'
const N = Point.getN()
const G = Point.getG()

// Define some keys and an invoice number
const inv = Buffer.from("2345456868-0")
const a = PrivKey.fromWif('L4xQDGyjWrL44M3zwUjtujaESrZpFCqMLaQxHCCgLxvjuVFgFTSs')
const b = PrivKey.fromWif('Kwp8MkjuEwXtqmxdh7NMBm7U7ktkk2HwmbEsCBPsquqtcr18RyWW')

// Bob shares his Public Key
const B = G.mul(b.bn)
const aaaa = new PubKey(B)
console.log(aaaa.toString())

// Alice calculates their secret
const Sab = B.mul(a.bn)
const secret = Buffer.concat([Sab.x.toBuffer(), Sab.y.toBuffer()])


// Alice shares her Public Key
const A = G.mul(a.bn)

// Bob calculates their secret
const Sba = A.mul(b.bn)
const secretB = Buffer.concat([Sba.x.toBuffer(), Sba.y.toBuffer()])
console.log(secret.toString() === secretB.toString() ? 'secrets are the same' : 'secrets do not match')

// Both calculate the Hmac of the secret with the invoice number mod N and 
// point multiply the generator with the resulting scalar.
const h = Bn(Hash.hmac('sha256', secret, inv)).mod(N)
const H = G.mul(h)

// Alice adds Bob's key to the newly defined point to define a locking script Bob will be able to unlock.
const P = H.add(B)
const pubkey = new PubKey(P)
const script = Script.fromPubKeyHash(Hash.sha256Ripemd160(pubkey.toBuffer()))
console.log('output script: ' + script.toHex())

// Bob checks to see if he will be able to unlock the script using only information he has.
// The private key should be the result of the invoice secret Hmac plus Bob's private key, 
// mod N since we're using a finite field.
const p = b.bn.add(h).mod(N)
const privKey = new PrivKey(p)
console.log('private key: ' + privKey.toString())
const check = PubKey.fromPrivKey(privKey)
console.log(check.toString() === pubkey.toString() ? 'pubkeys match: ' + check.toString() : 'pubkeys do not match')
