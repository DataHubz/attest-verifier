# Attest unlock worker 1.2.0

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

- version: `1.2.0`
- SHA-256 of the build Attest serves: `3e5f6d0608dae4fd0914bc9f9ebdec794ec2dc2743b0e3c728a94d7b1839b722`
- anchored value: `sha256("attest.unlock-worker.v1|1.2.0|3e5f6d0608dae4fd0914bc9f9ebdec794ec2dc2743b0e3c728a94d7b1839b722")`

## Check it against Horizen

Attest serves a build only once its platform organization has anchored it on AttestRegistryV3
(`0xF44Ed281005c7d506Dc50829a3E24655837FBF75`) from its platform wallet (`0xdEa7B859DcBd34deB8dc910b5b36d6ACdBeC6F3a`).
`anchoredAt(wallet, value)` returns when; 0 means it isn't anchored.

`sw-monitor.mjs` does the whole check against what Attest serves now, with plain Node 18 or later and no dependencies:

```
node sw-monitor.mjs --expect 3e5f6d0608dae4fd0914bc9f9ebdec794ec2dc2743b0e3c728a94d7b1839b722
node sw-monitor.mjs --expect 3e5f6d0608dae4fd0914bc9f9ebdec794ec2dc2743b0e3c728a94d7b1839b722 --every 15
```

With `--expect` it also requires this exact build; without it, any build the platform wallet ever anchored passes. Run it
from outside Attest's infrastructure: a page can't vouch for the worker it serves.
