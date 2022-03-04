import protobufjs from "protobufjs";
import { existsSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import crypto from "libp2p-crypto";
import PeerId from "peer-id";
import CID from 'cids';
import { base58btc } from 'multiformats/bases/base58';
import varint from "varint";
import multihash from "multihashes";

let { secp256k1 } = crypto.keys.supportedKeys;

const kPath = './exportedPEM.key';
const pPath = './exportedProtobuf.key';
const pubPath = './exportedProtobufPub.key';
if (!existsSync(kPath)) {
    let newKeyPair = await secp256k1.generateKeyPair();
    let newKeyPairExported = await newKeyPair.export("");
    await writeFile(kPath, newKeyPairExported);
}

let newKeyPairImported = await crypto.keys.import(await readFile(kPath, "utf-8"), "");


await writeFile(pPath, crypto.keys.marshalPrivateKey(newKeyPairImported, "secp256k1"));
await writeFile(pubPath, crypto.keys.marshalPublicKey(newKeyPairImported.public, "secp256k1"));

let ipfsKey = await protobufjs.load('./key.proto');
let protobufKey = await readFile(pPath);
let protobufPubKey = await readFile(pubPath);
let results = { ...ipfsKey.nested };
delete results.KeyType;

results["PublicKey"] = ipfsKey.lookupType("PublicKey").decode(protobufPubKey);
results["PrivateKey"] = ipfsKey.lookupType("PrivateKey").decode(protobufKey);

console.log("results", results)
let pubKey = await secp256k1.unmarshalSecp256k1PublicKey(results.PublicKey.Data);
let privKey = await secp256k1.unmarshalSecp256k1PrivateKey(results.PrivateKey.Data);

let myPeerID = PeerId.createFromPrivKey(protobufKey);

const id = await privKey.id();

console.log(varint.encode(pubKey.bytes.length * 8));
console.log(Buffer.from(multihash.encode(pubKey.bytes, "identity")).toString('hex'))
let myCID = new CID(1, "libp2p-key", multihash.encode(pubKey.bytes, "identity"));
console.log(myCID.toString('base36'));
//kzwfwjn5ji4puvokmcszflj3po708zngzw9h9wr2g5w0tcg4jo36i73kumah3i3


