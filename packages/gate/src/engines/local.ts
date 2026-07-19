import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import type { ActionRequest, DecisionValue, PolicyEngine, PolicyEngineResult } from "../types.js";

// Local policy engine. Deny by default: a request that matches no allow rule is
// denied. Rules match on tool name (glob), arg content (regex over the JSON string
// of args), and named action classes. A malformed policy throws at construction so
// the gate can never be silently permissive.

interface CompiledClass {
  tools: RegExp[];
  argsRe?: RegExp;
}

interface CompiledRule {
  className?: string;
  tool?: RegExp;
  argsRe?: RegExp;
  effect: DecisionValue;
  reason: string;
}

function globToRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        out += ".*";
        i++;
      } else {
        out += "[^.]*";
      }
    } else {
      out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  // Case-insensitive: tool names vary in casing across frameworks, and a security
  // default should not be bypassable by changing case.
  return new RegExp("^" + out + "$", "i");
}

function isDecision(x: unknown): x is DecisionValue {
  return x === "allow" || x === "deny";
}

export class LocalPolicyEngine implements PolicyEngine {
  private readonly policyVersion: string;
  private readonly classes = new Map<string, CompiledClass>();
  private readonly rules: CompiledRule[] = [];

  constructor(policyPath: string) {
    let raw: unknown;
    try {
      raw = parseYaml(readFileSync(policyPath, "utf8"));
    } catch (e) {
      throw new Error(
        `malformed policy: cannot read or parse ${policyPath}: ${(e as Error).message}`,
      );
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("malformed policy: the root must be a mapping");
    }
    const doc = raw as Record<string, unknown>;
    this.policyVersion = typeof doc.version === "string" ? doc.version : "unversioned";

    const ac = doc.actionClasses;
    if (ac !== undefined) {
      if (typeof ac !== "object" || ac === null || Array.isArray(ac)) {
        throw new Error("malformed policy: actionClasses must be a mapping");
      }
      for (const [name, def] of Object.entries(ac as Record<string, unknown>)) {
        if (!def || typeof def !== "object" || Array.isArray(def)) {
          throw new Error(`malformed policy: actionClass ${name} must be a mapping`);
        }
        const d = def as Record<string, unknown>;
        const tools: RegExp[] = [];
        if (d.tools !== undefined) {
          if (!Array.isArray(d.tools))
            throw new Error(`malformed policy: actionClass ${name}.tools must be a list`);
          for (const g of d.tools) {
            if (typeof g !== "string")
              throw new Error(
                `malformed policy: actionClass ${name}.tools entries must be strings`,
              );
            tools.push(globToRegExp(g));
          }
        }
        let argsRe: RegExp | undefined;
        if (d.argsPattern !== undefined) {
          if (typeof d.argsPattern !== "string")
            throw new Error(`malformed policy: actionClass ${name}.argsPattern must be a string`);
          try {
            argsRe = new RegExp(d.argsPattern, "i");
          } catch (e) {
            throw new Error(
              `malformed policy: actionClass ${name}.argsPattern is not a valid regex: ${(e as Error).message}`,
            );
          }
        }
        this.classes.set(name, { tools, argsRe });
      }
    }

    const rulesRaw = doc.rules;
    if (rulesRaw !== undefined) {
      if (!Array.isArray(rulesRaw)) throw new Error("malformed policy: rules must be a list");
      rulesRaw.forEach((rr, i) => {
        if (!rr || typeof rr !== "object" || Array.isArray(rr))
          throw new Error(`malformed policy: rule ${i} must be a mapping`);
        const r = rr as Record<string, unknown>;
        if (!isDecision(r.effect))
          throw new Error(`malformed policy: rule ${i}.effect must be allow or deny`);
        const rule: CompiledRule = {
          effect: r.effect,
          reason: typeof r.reason === "string" ? r.reason : "",
        };
        if (r.class !== undefined) {
          if (typeof r.class !== "string")
            throw new Error(`malformed policy: rule ${i}.class must be a string`);
          if (!this.classes.has(r.class))
            throw new Error(`malformed policy: rule ${i} references unknown class ${r.class}`);
          rule.className = r.class;
        }
        if (r.tool !== undefined) {
          if (typeof r.tool !== "string")
            throw new Error(`malformed policy: rule ${i}.tool must be a string`);
          rule.tool = globToRegExp(r.tool);
        }
        if (r.argsPattern !== undefined) {
          if (typeof r.argsPattern !== "string")
            throw new Error(`malformed policy: rule ${i}.argsPattern must be a string`);
          try {
            rule.argsRe = new RegExp(r.argsPattern, "i");
          } catch (e) {
            throw new Error(
              `malformed policy: rule ${i}.argsPattern is not a valid regex: ${(e as Error).message}`,
            );
          }
        }
        if (rule.className === undefined && rule.tool === undefined && rule.argsRe === undefined) {
          throw new Error(`malformed policy: rule ${i} must specify class, tool, or argsPattern`);
        }
        this.rules.push(rule);
      });
    }
  }

  version(): string {
    return this.policyVersion;
  }

  private matchesClass(name: string, tool: string, argsStr: string): boolean {
    const c = this.classes.get(name);
    if (!c) return false;
    const toolMatch = c.tools.length === 0 ? true : c.tools.some((re) => re.test(tool));
    if (!toolMatch) return false;
    if (c.argsRe && !c.argsRe.test(argsStr)) return false;
    return true;
  }

  async evaluate(req: ActionRequest): Promise<PolicyEngineResult> {
    const tool = String(req.tool ?? "");
    let argsStr: string;
    try {
      argsStr = JSON.stringify(req.args ?? null) ?? "null";
    } catch {
      // Args that cannot be serialized cannot be evaluated safely. Deny.
      return {
        decision: "deny",
        reason: "fail-closed: args are not serializable",
        policyVersion: this.policyVersion,
      };
    }

    for (const rule of this.rules) {
      let match: boolean;
      if (rule.className !== undefined) {
        match = this.matchesClass(rule.className, tool, argsStr);
        if (match && rule.tool) match = rule.tool.test(tool);
        if (match && rule.argsRe) match = rule.argsRe.test(argsStr);
      } else {
        match = rule.tool ? rule.tool.test(tool) : true;
        if (match && rule.argsRe) match = rule.argsRe.test(argsStr);
      }
      if (match) {
        const reason =
          rule.reason || `${rule.effect} by ${rule.className ? `class ${rule.className}` : "rule"}`;
        return { decision: rule.effect, reason, policyVersion: this.policyVersion };
      }
    }
    return {
      decision: "deny",
      reason: "no matching rule (deny by default)",
      policyVersion: this.policyVersion,
    };
  }
}
