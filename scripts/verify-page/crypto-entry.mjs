// The only third-party code that ends up in docs/verify/index.html.
//
// Two primitives cannot be taken from the browser:
//
//   SHA3-512 — SubtleCrypto.digest supports SHA-1 and the SHA-2 family only.
//   SHA3 is a different construction (Keccak sponge, not Merkle-Damgard) and no
//   browser exposes it. Receipts are hashed with SHA3-512 throughout, so it has
//   to be vendored.
//
//   Ed25519 — available as SubtleCrypto since Chrome 137, Firefox 129 and
//   Safari 17, but not before, and not at all in some embedded webviews. The
//   page prefers WebCrypto and falls back to this.
//
// Both come from @noble, which is audited and dependency-free. esbuild inlines
// this into one <script> so the page has no network dependency of any kind.
import { sha3_512 } from "@noble/hashes/sha3";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";

// @noble/ed25519 v3 keeps the hash injectable rather than bundling one.
ed.hashes.sha512 = sha512;

globalThis.EGVendor = {
  sha3_512,
  ed25519Verify(sig, msg, pub) {
    try {
      return ed.verify(sig, msg, pub);
    } catch {
      // A malformed signature or a non-canonical point is a failed
      // verification, not a crash. verify.ts makes the same choice.
      return false;
    }
  },
};
