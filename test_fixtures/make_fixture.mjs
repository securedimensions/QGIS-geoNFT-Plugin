// Writes endorsed_mint.json: one closed deployment, complete and consistent, with
// throwaway keys only (never the real CAs or a real drone key).
//
//   node test_fixtures/make_fixture.mjs        (needs node >= 18 and openssl on PATH)
//
// The deployment has three observations: two position fixes and one picture,
// stored in server order seq 1, 2, 3 while the drone signed them as n = 1, 3, 2
// (the picture took longer to pin). The gateway sealed its chain with n = 4.
// Every observation carries an ES256 DPoP proof by the drone key with the
// drone-chain claims boot, n, prev and plh or imgh. The manifest follows
// connected-systems/deploymentChain.mjs, and the deployment NFT is a
// MintDeployment transaction signed like Fabric peers sign it, by SecdMSP and
// GeoidworksMSP peers, in the shape the ledger API (geoNFT-Fabric/ledger-api)
// decodes it. Extra endorsements: EngineeringMSP, a SecdMSP client certificate
// and a GeoidworksMSP peer from a rogue CA with the same name.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEPLOYMENT_ID = 'dep-0bbec562-1526-516f-b2e5-eb6f03023f0d';
const OPERATOR = 'urn:ogc:feature:operator:op-zek6yrf5';
const DRONE_DID = 'did:indy:sandbox:JrqC2m6GGcvkQUb7qXQiUV';
const BOOT = 'AAECAwQFBgc'; // 8 bytes 00…07
const MINTED_AT = '2027-01-15T09:00:05.000Z';

const sha = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');

// RFC 8785 for the values used here (strings, safe integers, short decimals, objects, arrays).
function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
}
const canonicalHash = (doc) => sha(canonicalize(doc)).toString('hex');

// ── Drone: key, DPoP proofs, chain ────────────────────────────────────────────

const drone = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = drone.publicKey.export({ format: 'jwk' });
const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
const cnfJkt = b64u(sha(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })));

function dpop(claims) {
  const header = b64u(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk }));
  const payload = b64u(JSON.stringify(claims));
  const signature = sign('sha256', Buffer.from(`${header}.${payload}`), { key: drone.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${header}.${payload}.${b64u(signature)}`;
}

const droneGenesis = sha(`tcs-drone-chain-v1:${DEPLOYMENT_ID}:${fromB64u(BOOT).toString('hex')}`);

// The gateway's own order: n = 1 fix, n = 2 picture, n = 3 fix.
const position = (time, ms, lat, lon, h, heading) => {
  const resultTime = new Date(Date.parse(time) + ms).toISOString();
  // codec.c writes this exact layout, which is already RFC 8785.
  return `{"phenomenonTime":"${time}","result":{"h":${h},"heading":${heading},"lat":${lat},"lon":${lon}},"resultTime":"${resultTime}"}`;
};
const picture = Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
  Buffer.from('throwaway test picture for the certificate review plugin'),
  Buffer.from([0xff, 0xd9]),
]);

// CIDv1, raw codec, sha2-256: what Kubo answers for a single-block file with cid-version=1.
function rawCid(bytes) {
  const raw = Buffer.concat([Buffer.from([0x01, 0x55, 0x12, 0x20]), sha(bytes)]);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let out = 'b';
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

const signedByDrone = [
  { kind: 'position', datastreamId: 'ds-position', body: position('2026-11-17T08:10:00.000Z', 37, 48.137154, 11.576124, 12.5, 90) },
  { kind: 'image', datastreamId: 'ds-image', bytes: picture, time: '2026-11-17T08:10:01.000Z' },
  { kind: 'position', datastreamId: 'ds-position', body: position('2026-11-17T08:10:02.000Z', 41, 48.137301, 11.576388, 13.25, 92.5) },
];

let prev = droneGenesis;
let iat = Math.floor(Date.parse('2026-11-17T08:10:00.000Z') / 1000);
signedByDrone.forEach((obs, index) => {
  const n = index + 1;
  const digest = obs.kind === 'image' ? sha(obs.bytes) : sha(obs.body);
  const claims = {
    jti: b64u(randomBytes(12)),
    htm: 'POST',
    htu: `https://cs.geonft.eu/datastreams/${obs.datastreamId}/observations`,
    iat: iat++,
    ath: b64u(sha(`access-token-${n}`)),
    deployment: DEPLOYMENT_ID,
    boot: BOOT,
    n,
    prev: b64u(prev),
    [obs.kind === 'image' ? 'imgh' : 'plh']: b64u(digest),
  };
  obs.n = n;
  obs.proof = dpop(claims);
  obs.prev = prev.toString('hex');
  obs.link = sha(prev, digest);
  prev = obs.link;
});
const droneHead = prev;

// The seal: the last link of the segment.
const sealDoc = canonicalize({ boot: BOOT, deployment: DEPLOYMENT_ID, head: b64u(droneHead), n: 4, type: 'seal' });
const sealProof = dpop({
  jti: b64u(randomBytes(12)),
  htm: 'POST',
  htu: `https://cs.geonft.eu/deployments/${DEPLOYMENT_ID}/seal`,
  iat: iat++,
  ath: b64u(sha('access-token-seal')),
  deployment: DEPLOYMENT_ID,
  boot: BOOT,
  n: 4,
  prev: b64u(droneHead),
  plh: b64u(sha(sealDoc)),
});

// ── Connected Systems: server order, anchors, lineage, observations ──────────

const cid = rawCid(picture);
const imageResult = {
  contentType: 'application/octet-stream',
  cid,
  url: `https://ipfs.geonft.eu/ipfs/${cid}`,
  sha256: sha(picture).toString('hex'),
};
const serverOrder = [signedByDrone[0], signedByDrone[2], signedByDrone[1]];
let serverHead = sha(`tcs-deployment-chain-v1:${DEPLOYMENT_ID}`);
const lineageItems = [];
const observations = [];
serverOrder.forEach((obs, index) => {
  const seq = index + 1;
  const id = 4294967296 + seq;
  const doc = obs.kind === 'image' ? { deploymentId: DEPLOYMENT_ID, result: imageResult } : JSON.parse(obs.body);
  const anchorHash = canonicalHash(doc);
  serverHead = sha(serverHead, Buffer.from(anchorHash, 'hex'));
  lineageItems.push({
    seq,
    id,
    anchorHash,
    chainHash: serverHead.toString('hex'),
    droneBoot: BOOT,
    droneN: obs.n,
    dronePrev: obs.prev,
    droneLink: obs.link.toString('hex'),
    proof: obs.proof,
  });
  const last = observations.findLast((o) => o.featureOfInterest)?.featureOfInterest;
  observations.push({
    id,
    type: 'Observation',
    datastreamId: obs.datastreamId,
    deploymentId: DEPLOYMENT_ID,
    phenomenonTime: obs.kind === 'image' ? obs.time : doc.phenomenonTime,
    resultType: obs.kind === 'image' ? 'image' : 'telemetry',
    result: obs.kind === 'image' ? imageResult : doc.result,
    droneDid: DRONE_DID,
    receivedVia: 'http',
    anchorHash,
    chainHash: serverHead.toString('hex'),
    droneN: obs.n,
    droneLink: obs.link.toString('hex'),
    featureOfInterest: obs.kind === 'image' ? last : { type: 'Point', coordinates: [doc.result.lon, doc.result.lat] },
  });
});

const manifest = {
  v: 1,
  deploymentId: DEPLOYMENT_ID,
  systemId: 'sys-5f2c',
  droneDid: DRONE_DID,
  cnfJkt,
  operator: OPERATOR,
  validFrom: '2026-11-17T08:00:00.000Z',
  validTo: '2026-11-17T09:00:00.000Z',
  closeReason: 'sealed',
  serverChain: { alg: 'tcs-deployment-chain-v1', count: lineageItems.length, head: serverHead.toString('hex') },
  droneChain: {
    alg: 'tcs-drone-chain-v1',
    segments: [{ boot: BOOT, firstN: 1, lastN: 3, received: 3, missing: [], brokenLinks: 0, head: droneHead.toString('hex') }],
    seal: { boot: BOOT, n: 4, head: droneHead.toString('hex'), sealHash: sha(sealDoc).toString('hex') },
  },
};
const deploymentHash = canonicalHash(manifest);
const record = {
  tokenId: DEPLOYMENT_ID,
  owner: OPERATOR,
  deploymentHash,
  manifest,
  tokenUri: `https://cs.geonft.eu/deployments/${DEPLOYMENT_ID}/manifest`,
  mintedAt: MINTED_AT,
  mintedBy: 'SecdMSP/csapi@geonft.eu',
  txId: 'tx-1',
};

// ── Fabric: throwaway PKI and the signed MintDeployment ──────────────────────

const work = mkdtempSync(path.join(tmpdir(), 'cs-review-fixture-'));
const openssl = (...args) => execFileSync('openssl', args, { cwd: work, stdio: ['ignore', 'pipe', 'pipe'] });
const SUBJECT = '/C=US/ST=California/L=San Francisco';

function makeCa(name, cn) {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-days', '3650',
    '-keyout', `${name}.key`, '-out', `${name}.pem`, '-subj', `${SUBJECT}/O=${cn.slice(3)}/CN=${cn}`);
  return name;
}
function makeLeaf(name, ca, ou, cn) {
  openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `${SUBJECT}/OU=${ou}/CN=${cn}`);
  openssl('x509', '-req', '-in', `${name}.csr`, '-CA', `${ca}.pem`, '-CAkey', `${ca}.key`, '-CAcreateserial',
    '-sha256', '-days', '3650', '-out', `${name}.pem`);
  return { key: readFileSync(path.join(work, `${name}.key`)), pem: readFileSync(path.join(work, `${name}.pem`)) };
}

let fixture;
try {
  makeCa('secdCa', 'ca.geonft.eu');
  makeCa('engCa', 'ca.4113engineering.eu');
  makeCa('geoidCa', 'ca.geoidworks.eu');
  makeCa('rogueCa', 'ca.geoidworks.eu'); // same name, other key
  const signers = {
    secd: ['SecdMSP', makeLeaf('secd', 'secdCa', 'peer', 'peer0.geonft.eu')],
    geoid: ['GeoidworksMSP', makeLeaf('geoid', 'geoidCa', 'peer', 'peer0.geoidworks.eu')],
    eng: ['EngineeringMSP', makeLeaf('eng', 'engCa', 'peer', 'peer0.4113engineering.eu')],
    secdClient: ['SecdMSP', makeLeaf('secdClient', 'secdCa', 'client', 'User1@geonft.eu')],
    geoidRogue: ['GeoidworksMSP', makeLeaf('geoidRogue', 'rogueCa', 'peer', 'peer0.geoidworks.eu')],
  };

  // Protobuf: only length-delimited and varint fields are needed.
  const varint = (n) => {
    const out = [];
    let v = BigInt(n);
    do {
      let byte = Number(v & 0x7fn);
      v >>= 7n;
      if (v) byte |= 0x80;
      out.push(byte);
    } while (v);
    return Buffer.from(out);
  };
  const bytesField = (number, value) => {
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
    return Buffer.concat([varint((number << 3) | 2), varint(buf.length), buf]);
  };
  const intField = (number, value) => Buffer.concat([varint(number << 3), varint(value)]);
  const msg = (...fields) => Buffer.concat(fields);

  const compositeKey = (type, ...attrs) => `\u0000${type}\u0000${attrs.map((a) => `${a}\u0000`).join('')}`;
  const kvWrite = (key, value) => msg(bytesField(1, key), bytesField(3, value));
  const kvRwSet = msg(
    bytesField(3, kvWrite(compositeKey('deployment', DEPLOYMENT_ID), JSON.stringify(record))),
    bytesField(3, kvWrite(compositeKey('dephash', deploymentHash), DEPLOYMENT_ID)),
  );
  const txRwSet = msg(bytesField(2, msg(bytesField(1, 'deployments'), bytesField(2, kvRwSet))));
  const chaincodeAction = msg(
    bytesField(1, txRwSet),
    bytesField(3, msg(intField(1, 200))),
    bytesField(4, msg(bytesField(2, 'deployments'), bytesField(3, '1.0'))),
  );
  const prp = msg(bytesField(1, sha('MintDeployment proposal tx-1')), bytesField(2, chaincodeAction));

  const endorsements = {};
  const subjects = {};
  for (const [name, [mspId, leaf]] of Object.entries(signers)) {
    const endorser = msg(bytesField(1, mspId), bytesField(2, leaf.pem));
    endorsements[name] = {
      endorser: endorser.toString('base64'),
      signature: sign('sha256', Buffer.concat([prp, endorser]), leaf.key).toString('base64'),
    };
    const ou = name === 'secdClient' ? 'client' : 'peer';
    const cn = execFileSync('openssl', ['x509', '-noout', '-subject', '-nameopt', 'multiline'], { input: leaf.pem })
      .toString().match(/commonName\s*=\s*(.+)/)[1].trim();
    subjects[name] = `C=US, ST=California, L=San Francisco, OU=${ou}, CN=${cn}`;
  }
  const pem = (name) => readFileSync(path.join(work, `${name}.pem`), 'ascii');

  fixture = {
    about: 'Generated by test_fixtures/make_fixture.mjs with throwaway keys (not the real CAs, not a real drone): a closed, sealed '
      + 'deployment with its lineage, observations and picture, and its MintDeployment transaction signed like Fabric peers '
      + 'sign it, decoded like ledger-api/dist/transaction.js decodes it.',
    record,
    transaction: {
      txId: 'tx-1',
      validationCode: 0,
      validation: 'VALID',
      blockNumber: 4711,
      timestamp: MINTED_AT,
      chaincode: 'deployments',
      endorsements: ['secd', 'geoid'].map((name) => ({ mspId: signers[name][0], subject: subjects[name] })),
      endorsedAction: {
        proposalResponsePayload: prp.toString('base64'),
        endorsements: [endorsements.secd, endorsements.geoid],
      },
    },
    endorsements,
    trust: { SecdMSP: pem('secdCa'), EngineeringMSP: pem('engCa'), GeoidworksMSP: pem('geoidCa') },
    lineage: { deploymentId: DEPLOYMENT_ID, items: lineageItems, seal: { doc: sealDoc, proof: sealProof }, links: [] },
    observations,
    images: { [imageResult.url]: picture.toString('base64') },
    droneJwk: publicJwk,
  };
} finally {
  rmSync(work, { recursive: true, force: true });
}

writeFileSync(path.join(HERE, 'endorsed_mint.json'), `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote endorsed_mint.json: ${DEPLOYMENT_ID} ${deploymentHash}`);
