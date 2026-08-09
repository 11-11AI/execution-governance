// Asks the gate whether this push is allowed, and in enforce mode exits
// non-zero to block it. Called by the pre-push hook, which does the git-side
// work of detecting a force push and hands the result here as flags.
//
// Everything below uses the published @11ai/execution-governance API and
// nothing else, so it runs against the package you can install from npm.
//
// MODES
// -----
// shadow (default)  decide, record a receipt, never block. This is the mode to
//                   start in: you find out what the policy would have done to
//                   your actual workflow before it can cost you a push.
// enforce           a deny exits 1 and git abandons the push.
//
// Shadow first is not timidity. A policy that blocks the wrong thing on day one
// gets uninstalled on day one, and an uninstalled gate denies nothing at all.
//
// FAIL-CLOSED, AND WHERE IT APPLIES
// ---------------------------------
// In enforce mode an error blocks the push. A gate that lets the action through
// when it cannot reach a decision is not a gate. In shadow mode an error does
// not block, because shadow's entire contract is that it never blocks -- a
// shadow deployment that started failing pushes would be a broken promise, and
// worse, would train people to remove it.
import { readFileSync } from "node:fs";
import { createGate, DeniedError, fromB64u } from "@11ai/execution-governance";

const args = Object.fromEntries(
  process.argv
    .slice(2)
    .reduce(
      (acc, x, i, arr) => (x.startsWith("--") ? [...acc, [x.slice(2), arr[i + 1]]] : acc),
      [],
    ),
);

const mode = args.mode ?? process.env.EG_MODE ?? "shadow";
const enforce = mode === "enforce";
const tag = enforce ? "[ENFORCE]" : "[SHADOW]";
const policyPath = process.env.EG_POLICY ?? "examples/git-hook/eg-policy.yaml";

// A stable signing key makes receipts verifiable across runs. Without one the
// SDK generates an ephemeral key and says so; the hook still works, but the
// receipt file stops being useful as a record the moment the process exits.
let signingKey;
if (process.env.EG_SIGNING_KEY) {
  signingKey = fromB64u(readFileSync(process.env.EG_SIGNING_KEY, "utf8").trim());
}

// One exit path, so there is exactly one place where this can decide to block.
function finish(decision, reason) {
  console.error(`${tag} execution-governance: ${decision} — ${reason}`);
  process.exit(enforce && decision !== "allow" ? 1 : 0);
}

try {
  const gate = createGate({
    policy: policyPath,
    ...(signingKey ? { signingKey } : {}),
  });

  // authorize() rather than govern(): there is no function to run here. git is
  // the thing that will or will not proceed, based on this process's exit code.
  const decision = await gate.authorize({
    sessionId: process.env.EG_SESSION ?? `push-${process.pid}`,
    tool: "git.push",
    args: {
      branch: args.branch ?? "",
      remote: args.remote ?? "",
      force: args.force === "true",
    },
  });

  finish(decision.decision, decision.reason);
} catch (err) {
  if (err instanceof DeniedError) {
    finish(err.decision.decision, err.decision.reason);
  }
  console.error(
    `[execution-governance] ${err.message}` +
      (enforce ? " — failing closed, push blocked" : " — shadow mode, not blocking"),
  );
  process.exit(enforce ? 1 : 0);
}
