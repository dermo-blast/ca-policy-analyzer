/**
 * The EAM companion-policy check must read tenant state, not just policy shape.
 * Run: npx tsx scripts/check-eam-risk-remediation.ts
 *
 * "Require risk remediation" + an authentication strength only strands users
 * who are actually enrolled in an External Authentication Method. Whether the
 * tenant has one is knowable - it is in the authentication methods policy - so
 * the check consults it instead of assuming.
 */

import assert from "node:assert/strict";
import { checkPolicyExclusions } from "../src/data/known-exclusions";
import type {
  ConditionalAccessPolicy,
  ExternalAuthMethodState,
} from "../src/lib/graph-client";

const EXCLUSION_ID = "user-risk-remediation-no-eam-companion";

function riskPolicy(
  overrides: Partial<ConditionalAccessPolicy> = {}
): ConditionalAccessPolicy {
  return {
    id: "p-risk",
    displayName: "Global - High risk user - Risk remediation",
    state: "enabled",
    createdDateTime: "",
    modifiedDateTime: "",
    conditions: {
      users: {
        includeUsers: ["All"],
        excludeUsers: [],
        includeGroups: [],
        excludeGroups: [],
        includeRoles: [],
        excludeRoles: [],
        includeGuestsOrExternalUsers: null,
        excludeGuestsOrExternalUsers: null,
      },
      applications: {
        includeApplications: ["All"],
        excludeApplications: [],
        includeUserActions: [],
        includeAuthenticationContextClassReferences: [],
        applicationFilter: null,
      },
      clientAppTypes: ["all"],
      platforms: null,
      locations: null,
      userRiskLevels: ["high"],
      signInRiskLevels: [],
      devices: null,
      clientApplications: null,
    },
    grantControls: {
      operator: "AND",
      builtInControls: ["riskRemediation"],
      customAuthenticationFactors: [],
      termsOfUse: [],
      authenticationStrength: {
        id: "as-1",
        displayName: "Phishing-resistant MFA",
        policyType: "custom",
        requirementsSatisfied: "mfa",
        allowedCombinations: ["fido2"],
      },
    },
    sessionControls: null,
    ...overrides,
  } as ConditionalAccessPolicy;
}

function eam(
  overrides: Partial<ExternalAuthMethodState> = {}
): ExternalAuthMethodState {
  const enabled = [
    {
      id: "eam-1",
      displayName: "Duo",
      state: "enabled",
      includeTargets: ["all_users"],
      excludeTargets: [],
    },
  ];
  return { all: enabled, enabled, targetsAllUsers: true, ...overrides };
}

const fired = (
  policy: ConditionalAccessPolicy,
  state?: ExternalAuthMethodState | null
) => checkPolicyExclusions(policy, undefined, state).find((f) => f.exclusion.id === EXCLUSION_ID);

const checks: Array<[string, () => void]> = [
  [
    "a tenant with an enabled EAM still gets the finding",
    () => {
      const f = fired(riskPolicy(), eam());
      assert.ok(f, "the gap is real when EAM exists");
      assert.equal(f!.exclusion.severity, "high");
    },
  ],
  [
    "the finding names the provider and says all users are in scope",
    () => {
      const f = fired(riskPolicy(), eam())!;
      assert.match(f.result.detail, /"Duo"/);
      assert.match(f.result.detail, /targets all users/);
    },
  ],
  [
    "a tenant with NO External Authentication Method is not flagged",
    () => {
      const none: ExternalAuthMethodState = {
        all: [],
        enabled: [],
        targetsAllUsers: false,
      };
      assert.equal(fired(riskPolicy(), none), undefined);
    },
  ],
  [
    "an EAM that exists but is disabled cannot strand anyone",
    () => {
      const disabled: ExternalAuthMethodState = {
        all: [
          {
            id: "eam-1",
            displayName: "Duo",
            state: "disabled",
            includeTargets: ["all_users"],
            excludeTargets: [],
          },
        ],
        enabled: [],
        targetsAllUsers: false,
      };
      assert.equal(fired(riskPolicy(), disabled), undefined);
    },
  ],
  [
    "unknown tenant state fails OPEN - never suppressed on a failed read",
    () => {
      // null = the authentication methods policy could not be read
      assert.ok(fired(riskPolicy(), null), "null must not suppress");
      assert.ok(fired(riskPolicy(), undefined), "undefined must not suppress");
      assert.match(
        fired(riskPolicy(), null)!.result.detail,
        /could not be read/,
        "an unverified finding must say so"
      );
    },
  ],
  [
    "a group-scoped EAM asks the reader to check overlap rather than asserting it",
    () => {
      const scoped: ExternalAuthMethodState = {
        all: [],
        enabled: [
          {
            id: "eam-1",
            displayName: "Okta Verify",
            state: "enabled",
            includeTargets: ["group-a", "group-b"],
            excludeTargets: [],
          },
        ],
        targetsAllUsers: false,
      };
      const f = fired(riskPolicy(), scoped)!;
      assert.match(f.result.detail, /2 group\(s\)/);
      assert.match(f.result.detail, /within this policy's user scope/);
    },
  ],
  [
    "policy shape still gates the check - EAM state alone never fires it",
    () => {
      // no user risk condition
      const noRisk = riskPolicy();
      noRisk.conditions.userRiskLevels = [];
      assert.equal(fired(noRisk, eam()), undefined);

      // no authentication strength: EAM users can satisfy built-in MFA
      const noStrength = riskPolicy();
      noStrength.grantControls!.authenticationStrength = undefined;
      assert.equal(fired(noStrength, eam()), undefined);

      // disabled policy enforces nothing
      const off = riskPolicy({ state: "disabled" });
      assert.equal(fired(off, eam()), undefined);
    },
  ],
];

let failed = 0;
for (const [name, fn] of checks) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failed += 1;
    console.error(`  FAIL ${name}`);
    console.error(`       ${e instanceof Error ? e.message : String(e)}`);
  }
}

console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
if (failed > 0) process.exit(1);
