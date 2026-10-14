# Attest unlock worker 1.1.0

The service worker Attest serves at `https://attest.datahubz.com/sw.js`. On a device its owner turned on, it unlocks a
document for a new signer automatically: it opens the sealed signer list and the device's copy of the document key, checks
the signer's key against Attest's public key directory on Horizen, and passes the document key on only when every check
passes. This folder is its complete source and the build that makes the exact bytes Attest serves.

## Build it and compare

```
npm install
node build.mjs sw.js
```

It prints the version, the SHA-256 of the build and the value anchored on Horizen:

- version: `1.1.0`
- SHA-256 of the build Attest serves: `a8449e6466470ef99abd14e213d1b5aef2a3c1d03d3b64dfb8d65c6d47765b2c`
- anchored value: `sha256("attest.unlock-worker.v1|1.1.0|a8449e6466470ef99abd14e213d1b5aef2a3c1d03d3b64dfb8d65c6d47765b2c")`

## Check it against Horizen

Attest serves a build only once its platform organization has anchored it on AttestRegistryV3
(`0xF44Ed281005c7d506Dc50829a3E24655837FBF75`) from its platform wallet (`0xdEa7B859DcBd34deB8dc910b5b36d6ACdBeC6F3a`).
`anchoredAt(wallet, value)` returns when; 0 means it isn't anchored.

`sw-monitor.mjs` does the whole check against what Attest serves now, with plain Node 18 or later and no dependencies:

```
node sw-monitor.mjs --expect a8449e6466470ef99abd14e213d1b5aef2a3c1d03d3b64dfb8d65c6d47765b2c
node sw-monitor.mjs --expect a8449e6466470ef99abd14e213d1b5aef2a3c1d03d3b64dfb8d65c6d47765b2c --every 15
```

With `--expect` it also requires this exact build; without it, any build the platform wallet ever anchored passes. Run it
from outside Attest's infrastructure: a page can't vouch for the worker it serves.
