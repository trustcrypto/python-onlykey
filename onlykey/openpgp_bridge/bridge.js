// openpgp-bridge.js — Node bridge over the modified OpenPGP.js (PQC-aware).
// Commands:
//   parse <keyfile> [passphrase]   -> JSON: composite -> 160B blob; RSA -> p/q; ECC -> scalar+curve
'use strict';
const fs = require('fs');
const path = require('path');

function loadOpenPGP(p) {
  let m = null; try { m = require(p); } catch (e) {}
  if (m && typeof m.generateKey === 'function') return m;
  return new Function(fs.readFileSync(p, 'utf8') + '\n;return openpgp;')();
}
const hex = (u8) => Buffer.from(u8).toString('hex');
const CURVE = { ed25519: 1, curve25519: 4, nistp256: 2, p256: 2, secp256k1: 3 };
const normCurve = (c) => String(c || '').replace(/legacy$/i, '').toLowerCase();

async function parseKey(openpgp, armored, passphrase) {
  let key = await openpgp.readPrivateKey({ armoredKey: armored });
  if (!key.isDecrypted()) {
    if (!passphrase) throw new Error('key is encrypted; passphrase required');
    key = await openpgp.decryptKey({ privateKey: key, passphrase });
  }
  const primary = key.keyPacket;
  const pp = primary.privateParams || {};
  const sub0 = key.subkeys[0] && key.subkeys[0].keyPacket;
  const sp0 = sub0 && sub0.privateParams || {};
  // ---- PQC composite (ML-DSA-65 + ML-KEM-768) -> 160-byte OnlyKey blob ----
  if (pp.mldsaSeed || sp0.mlkemSeed) {
    const blob = Buffer.concat([
      Buffer.from(pp.eccSecretKey), Buffer.from(pp.mldsaSeed),
      Buffer.from(sp0.eccSecretKey), Buffer.from(sp0.mlkemSeed),
    ]);
    if (blob.length !== 160) throw new Error('composite blob ' + blob.length + ' != 160');
    return { type: 'pqc-composite', blob: blob.toString('hex') };
  }
  // ---- classic RSA / ECC ----
  const one = (packet) => {
    const p = packet.privateParams || {};
    if (p.p && p.q) return { kind: 'rsa', p: hex(p.p), q: hex(p.q) };
    const s = p.d || p.seed || p.eccSecretKey || p.secretKey;
    let cn = '';
    try { cn = packet.getAlgorithmInfo().curve; } catch (e) { try { cn = packet.publicParams.oid.getName(); } catch (_) {} }
    return { kind: 'ecc', s: s ? hex(s) : null, curve: CURVE[normCurve(cn)] || 0 };
  };
  const keys = [Object.assign({ name: 'Primary Key' }, one(primary))];
  for (const sk of key.subkeys) keys.push(Object.assign({ name: 'Subkey' }, one(sk.keyPacket)));
  return { type: keys.some(k => k.kind === 'rsa') ? 'rsa' : 'ecc', keys };
}

(async () => {
  const [cmd, keyfile, passphrase] = process.argv.slice(2);
  const openpgp = loadOpenPGP(path.join(__dirname, 'openpgp.js'));
  if (cmd === 'parse') {
    const out = await parseKey(openpgp, fs.readFileSync(keyfile, 'utf8'), passphrase);
    process.stdout.write(JSON.stringify(out));
  } else throw new Error('unknown command: ' + cmd);
})().catch((e) => { process.stderr.write('ERROR: ' + e.message + '\n'); process.exit(1); });
