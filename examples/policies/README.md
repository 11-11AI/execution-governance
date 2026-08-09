# Starter policies

Copy one, edit it, point the gate at it. Each is **deny by default**: a tool
call matching no allow rule is denied.

| Policy                                                                                 | For                                                                                               |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [`browser-agent.yaml`](browser-agent.yaml)                                             | an agent driving a browser, where attacker-controlled page text is the normal operating condition |
| [`finance-agent.yaml`](finance-agent.yaml)                                             | an agent with access to money movement                                                            |
| [`../git-hook/eg-policy.yaml`](../git-hook/eg-policy.yaml)                             | a coding agent with push access                                                                   |
| [`../../tests/fixtures/starter-policy.yaml`](../../tests/fixtures/starter-policy.yaml) | the general starter: exfiltration, irreversible actions, spend, identity change                   |

Validate before you rely on one:

```bash
npx @11ai/mcp-gate --validate --policy examples/policies/browser-agent.yaml
```

## Rule order is load-bearing

Rules are evaluated in order and **the first match wins**. Every file here puts
its denials above its allows. Moving a broad allow upward will silently swallow
the denials below it, and the policy will still validate — a policy can be well
formed and wrong at the same time.

## These are starting points, not compliance controls

They deny categories of action. They do not know your spending limits, your
segregation-of-duties rules, or which counterparties you have approved. The
finance policy in particular is the most restrictive of the three because a
completed transfer has no undo, but it is not a substitute for controls in the
system that holds the money.

Each policy is covered by tests asserting it denies what its comments claim,
rather than only that it parses.
