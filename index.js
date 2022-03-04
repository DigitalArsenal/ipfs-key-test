import protobufjs from "protobufjs";
import { existsSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import crypto from "libp2p-crypto";
import atob from "atob";
import btoa from "btoa";
import PeerId from "peer-id";

import { base16 } from 'multiformats/bases/base16';
import { base36 } from 'multiformats/bases/base36';
import { base58btc } from 'multiformats/bases/base58';
import { identity } from 'multiformats/hashes/identity';


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


await writeFile(pPath, crypto.keys.marshalPrivateKey(newKeyPairImported));
await writeFile(pubPath, crypto.keys.marshalPublicKey(newKeyPairImported.public));

let ipfsKey = await protobufjs.load('./key.proto');
let protobufKey = await readFile(pPath);
let protobufPubKey = await readFile(pubPath);
let results = { ...ipfsKey.nested };
delete results.KeyType;

results["PublicKey"] = ipfsKey.lookupType("PublicKey").decode(protobufPubKey);
results["PrivateKey"] = ipfsKey.lookupType("PrivateKey").decode(protobufKey);

console.log(results)
let pubKey = await secp256k1.unmarshalSecp256k1PublicKey(results.PublicKey.Data);

console.log(pubKey.id);

//kzwfwjn5ji4puvokmcszflj3po708zngzw9h9wr2g5w0tcg4jo36i73kumah3i3
/*

console.log(Buffer.from(results.PrivateKey.Data).toString('hex'));



const key = await secp256k1.unmarshalSecp256k1PrivateKey(protobufKey);
const id = await key.id();
console.log(id);
console.log(base58btc.encode(Buffer.from(id)));
//kzwfwjn5ji4pun29gq655o0bpfd89mg3ts36u5p65cza0pz0jzrb1prhlccczhs
*/

