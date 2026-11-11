/**
 * The Policies and Policy Plans tabs describe a policy in one line - users →
 * apps → grant. That line must not drop a condition that changes what the
 * policy does: a "block device code flow" policy that renders as
 * "All users → All cloud apps → Block access" reads as a tenant-wide block.
 * And the Plans tab must name who a plan includes and excludes, the way the
 * Policies tab's Condition Details table does.
 * Run: npx tsx scripts/check-policy-display.tsx
 */

import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";
import {
  buildTenantContextFromOfflineExport,
  type OfflineExportPayload,
} from "../src/lib/offline-import";
import { analyzeAllPolicies } from "../src/lib/analyzer";
import {
  buildUserConditionRows,
  summarizeConditionSet,
  summarizeControls,
} from "../src/lib/policy-plan-visualizer";
import {
  collectPlanUserIds,
  type ConditionalAccessPolicyPlanWithRules,
} from "../src/lib/graph-client";
import { PolicyPlansView } from "../src/components/policy-plans-view";
import { ROLE_NAME_MAP } from "../src/lib/role-names";

const ALL_GUEST_TYPES =
  "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider";
const GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10";
const BREAK_GLASS_GROUP = "bbbbbbbb-0000-0000-0000-000000000001";
const SERVICE_ACCOUNTS_GROUP = "bbbbbbbb-0000-0000-0000-000000000002";
const PLAN_ONLY_GROUP = "bbbbbbbb-0000-0000-0000-000000000003";

function offlinePolicy(
  id: string,
  displayName: string,
  users: Record<string, unknown>,
  grant: Record<string, unknown>,
  extraConditions: Record<string, unknown> = {}
) {
  return {
    Id: id,
    DisplayName: displayName,
    State: "enabled",
    CreatedDateTime: "2026-01-01T00:00:00Z",
    ModifiedDateTime: null,
    Conditions: {
      Applications: {
        IncludeApplications: ["All"],
        ExcludeApplications: [],
        IncludeUserActions: [],
        IncludeAuthenticationContextClassReferences: [],
      },
      ClientAppTypes: ["all"],
      Users: {
        IncludeUsers: [],
        ExcludeUsers: [],
        IncludeGroups: [],
        ExcludeGroups: [],
        IncludeRoles: [],
        ExcludeRoles: [],
        ...users,
      },
      SignInRiskLevels: [],
      UserRiskLevels: [],
      ...extraConditions,
    },
    GrantControls: grant,
  };
}

const payload = {
  tenantId: "00000000-0000-0000-0000-000000000000",
  tenantDisplayName: "Display Fixture",
  conditionalAccessPolicies: [
    offlinePolicy(
      "aaaaaaaa-0000-0000-0000-000000000001",
      "Block device code flow",
      { IncludeUsers: ["All"], ExcludeGroups: [BREAK_GLASS_GROUP] },
      { Operator: "OR", BuiltInControls: ["block"], CustomAuthenticationFactors: [], TermsOfUse: [] },
      { AuthenticationFlows: { TransferMethods: "deviceCodeFlow" } }
    ),
    offlinePolicy(
      "aaaaaaaa-0000-0000-0000-000000000002",
      "Guests require MFA",
      {
        IncludeGuestsOrExternalUsers: {
          GuestOrExternalUserTypes: ALL_GUEST_TYPES,
          ExternalTenants: { MembershipKind: "all" },
        },
      },
      { Operator: "OR", BuiltInControls: ["mfa"], CustomAuthenticationFactors: [], TermsOfUse: [] }
    ),
    offlinePolicy(
      "aaaaaaaa-0000-0000-0000-000000000003",
      "Guests accept terms of use",
      {
        IncludeGuestsOrExternalUsers: {
          GuestOrExternalUserTypes: "b2bCollaborationGuest",
          ExternalTenants: { MembershipKind: "all" },
        },
      },
      { Operator: "OR", BuiltInControls: [], CustomAuthenticationFactors: [], TermsOfUse: ["tou-1"] }
    ),
  ],
  directoryObjects: [
    {
      Id: BREAK_GLASS_GROUP,
      AdditionalProperties: { "@odata.type": "#microsoft.graph.group", displayName: "Emergency Access" },
    },
  ],
} as unknown as OfflineExportPayload;

const ctx = buildTenantContextFromOfflineExport(payload);
const result = analyzeAllPolicies(ctx);
const viz = (name: string) => {
  const r = result.policyResults.find((p) => p.policy.displayName === name);
  assert.ok(r, `policy "${name}" missing from results`);
  return r.visualization;
};

/** A plan shaped like a real role-targeted plan: shared roles + shared exclusions. */
const plans: ConditionalAccessPolicyPlanWithRules[] = [
  {
    id: "plan-1",
    displayName: "Admins plan",
    sharedConditions: {
      users: {
        includeUsers: [],
        excludeUsers: [],
        includeGroups: [],
        excludeGroups: [BREAK_GLASS_GROUP, PLAN_ONLY_GROUP],
        includeRoles: [GLOBAL_ADMIN_ROLE],
        excludeRoles: [],
      },
    },
    rules: [
      {
        id: "rule-1",
        displayName: "Guests block admin portals",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: {
            includeUsers: [],
            excludeUsers: [],
            includeGroups: [],
            excludeGroups: [SERVICE_ACCOUNTS_GROUP],
            includeRoles: [],
            excludeRoles: [],
            excludeGuestsOrExternalUsers: {
              guestOrExternalUserTypes: "serviceProvider",
              externalTenants: { membershipKind: "all" },
            },
          },
          authenticationFlows: { transferMethods: "authenticationTransfer" },
        },
        controls: { grantControls: { operator: "OR", builtInControls: [], customAuthenticationFactors: [], termsOfUse: ["tou-1"] } },
      },
    ],
  },
];

const resolverMaps = {
  directoryObjects: new Map([
    [BREAK_GLASS_GROUP, { id: BREAK_GLASS_GROUP, displayName: "Emergency Access" }],
    [PLAN_ONLY_GROUP, { id: PLAN_ONLY_GROUP, displayName: "Plan-only Exclusions" }],
    [SERVICE_ACCOUNTS_GROUP, { id: SERVICE_ACCOUNTS_GROUP, displayName: "Service Accounts" }],
  ]),
};
const planContext = { namedLocations: [], servicePrincipals: new Map() };

function text(html: string): string {
  return html.replace(/<[^>]+>/g, " ").replace(/&#x27;|&apos;/g, "'").replace(/&amp;/g, "&").replace(/\s+/g, " ");
}

const checks: Array<[string, () => void]> = [
  [
    "Policies tab: a device-code-flow block names the flow, not just 'All users → Block'",
    () => {
      const v = viz("Block device code flow");
      assert.deepEqual(v.grantControls, ["🚫 Block access"]);
      assert.ok(v.conditions.includes("Authentication flows: Device code flow"), v.conditions.join(" | "));
    },
  ],
  [
    "Policies tab: a guest-only policy says guests, not '0 specific user/group/role targets'",
    () => {
      assert.equal(viz("Guests require MFA").targetUsers, "All guest / external user types");
      assert.equal(viz("Guests accept terms of use").targetUsers, "B2B Collaboration guests");
    },
  ],
  [
    "Policies tab: a terms-of-use-only grant is shown, not a blank label",
    () => {
      assert.deepEqual(viz("Guests accept terms of use").grantControls, ["📄 Accept terms of use"]);
    },
  ],
  [
    "Plans tab: rule summary shows authentication transfer and terms of use",
    () => {
      const rule = plans[0].rules[0];
      assert.ok(
        summarizeConditionSet(rule.conditions, planContext).conditions.includes(
          "Authentication flows: Authentication transfer"
        )
      );
      assert.deepEqual(summarizeControls(rule.controls).grantControls, ["📄 Accept terms of use"]);
    },
  ],
  [
    "Plans tab: shared guest targeting is summarized instead of 'Left to each rule'",
    () => {
      const summary = summarizeConditionSet(
        {
          users: {
            includeUsers: [],
            excludeUsers: [],
            includeGroups: [],
            excludeGroups: [BREAK_GLASS_GROUP],
            includeRoles: [],
            excludeRoles: [],
            includeGuestsOrExternalUsers: {
              guestOrExternalUserTypes: ALL_GUEST_TYPES,
              externalTenants: { membershipKind: "all" },
            },
          },
        },
        planContext
      );
      assert.equal(summary.targetUsers, "All guest / external user types");
    },
  ],
  [
    "Plans tab: shared conditions list included roles and excluded groups by name",
    () => {
      const rows = new Map(buildUserConditionRows(plans[0].sharedConditions, resolverMaps));
      assert.equal(rows.get("Include Roles"), "Global Admin");
      assert.equal(rows.get("Exclude Groups"), "Emergency Access, Plan-only Exclusions");
      assert.ok(!rows.has("Include Users"), "no empty Include Users row");
    },
  ],
  [
    "Plans tab: rule-level exclusions include guest types, by name",
    () => {
      const rows = new Map(buildUserConditionRows(plans[0].rules[0].conditions, resolverMaps));
      assert.equal(rows.get("Exclude Groups"), "Service Accounts");
      assert.equal(rows.get("Exclude Guests"), "Service provider users (all external tenants)");
    },
  ],
  [
    "Plans tab: no users block means no details rows (rule inherits from the plan)",
    () => {
      assert.deepEqual(buildUserConditionRows({ clientAppTypes: ["all"] }, resolverMaps), []);
      assert.deepEqual(buildUserConditionRows(undefined, resolverMaps), []);
    },
  ],
  [
    "role names are spelled correctly (Intune Administrator role)",
    () => {
      assert.equal(ROLE_NAME_MAP["3a2c62db-5318-420d-8d74-23affee5d9d5"], "Intune Admin");
    },
  ],
  [
    "scan resolves names for groups only a plan references, shared and rule-level",
    () => {
      const ids = collectPlanUserIds(plans);
      assert.ok(ids.includes(PLAN_ONLY_GROUP));
      assert.ok(ids.includes(SERVICE_ACCOUNTS_GROUP));
      assert.ok(ids.includes(GLOBAL_ADMIN_ROLE));
    },
  ],
  [
    "Plans tab renders the shared users table with named exclusions",
    () => {
      const html = text(
        renderToString(
          React.createElement(PolicyPlansView, {
            plans,
            policies: [],
            context: planContext,
            resolverMaps,
          })
        )
      );
      assert.ok(/Shared users/i.test(html), "shared users table missing");
      assert.ok(html.includes("Emergency Access, Plan-only Exclusions"), "excluded groups not named");
      assert.ok(html.includes("Global Admin"), "included role not named");
    },
  ],
];

let failed = 0;
for (const [name, fn] of checks) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL ${name}\n       ${(e as Error).message}`);
  }
}
console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
if (failed > 0) process.exit(1);
