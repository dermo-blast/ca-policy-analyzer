/**
 * Observed Conditional Access coverage gates the severity of a discovered app.
 * Run: npx tsx scripts/check-signin-app-coverage.ts
 *
 * The fixture holds four apps with IDENTICAL predicted impact - all four are
 * legacy-client sign-ins that the fixture's block policy would catch once a
 * service principal exists. Only their evidence differs, so any severity
 * difference here comes from the observed-coverage gate and nothing else.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildTenantContextFromOfflineExport,
  type OfflineExportPayload,
} from "../src/lib/offline-import";
import {
  analyzeSignInAppGap,
  classifyObservedCoverage,
  findNameMatchedServicePrincipals,
} from "../src/lib/signin-app-gap";

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../docs/fixtures/offline-export-ca-coverage.json"
);
const payload = JSON.parse(
  fs.readFileSync(fixturePath, "utf8")
) as OfflineExportPayload;

const gap = analyzeSignInAppGap(buildTenantContextFromOfflineExport(payload));
const byName = Object.fromEntries(gap.apps.map((a) => [a.displayName, a]));

const checks: Array<[string, () => void]> = [
  [
    "every fixture app is discovered, so severity is the only variable",
    () => {
      assert.equal(gap.apps.length, 5);
      for (const name of [
        "Covered App",
        "Excluded User App",
        "Unmatched App",
        "No Evidence App",
        "Fixture App",
      ]) {
        assert.ok(byName[name], `${name} missing from the discovered list`);
      }
    },
  ],
  [
    "every app would be blocked once registered - the prediction is identical",
    () => {
      assert.equal(
        gap.summary.wouldBlock,
        5,
        "fixture must keep predicted impact constant across every app"
      );
    },
  ],
  [
    "an app Conditional Access already evaluated is informational, not critical",
    () => {
      assert.equal(byName["Covered App"].severity, "info");
      assert.equal(byName["Covered App"].conditionalAccessStatus, "success");
    },
  ],
  [
    "a policy that matched the app but not the user is a user gap, graded low",
    () => {
      assert.equal(byName["Excluded User App"].severity, "low");
    },
  ],
  [
    "an app no policy matched keeps its critical grade",
    () => {
      assert.equal(byName["Unmatched App"].severity, "critical");
    },
  ],
  [
    "no evidence means no opinion - grading is unchanged",
    () => {
      assert.equal(byName["No Evidence App"].severity, "critical");
    },
  ],
  [
    "the summary counts observed coverage",
    () => {
      assert.equal(gap.summary.observedCovered, 1);
    },
  ],
  [
    "the finding says coverage exists rather than implying none",
    () => {
      const finding = gap.findings.find((f) => f.discoveredApps?.length)!;
      assert.match(finding.description, /already evaluated by Conditional Access/);
      assert.match(finding.description, /not new coverage/);
    },
  ],
  [
    "classifier: success and failure both mean Conditional Access reached the app",
    () => {
      assert.equal(classifyObservedCoverage("success", []), "covered");
      assert.equal(classifyObservedCoverage("failure", []), "covered");
      // Casing from Graph is not guaranteed
      assert.equal(classifyObservedCoverage("Success", []), "covered");
    },
  ],
  [
    "classifier: notApplied is read through the condition that failed",
    () => {
      assert.equal(
        classifyObservedCoverage("notApplied", [
          { conditionsNotSatisfied: "users" },
        ]),
        "userOutOfScope"
      );
      assert.equal(
        classifyObservedCoverage("notApplied", [
          { conditionsNotSatisfied: "application" },
        ]),
        "appUnmatched"
      );
      // A user-condition miss on any policy that DID match the app wins: it
      // proves the app is reachable, whatever the other policies did.
      assert.equal(
        classifyObservedCoverage("notApplied", [
          { conditionsNotSatisfied: "application" },
          { conditionsNotSatisfied: "users" },
        ]),
        "userOutOfScope"
      );
    },
  ],
  [
    "an app reusing an existing service principal's name is counted, not hidden",
    () => {
      assert.equal(gap.summary.nameMatchedExisting, 1);
      // It is still reported as missing a service principal, because the appId
      // that signed in genuinely has none. Suppressing it would hide the trap.
      assert.ok(byName["Fixture App"], "the recreated app must still be listed");
    },
  ],
  [
    "the finding explains the name collision with both app IDs",
    () => {
      const finding = gap.findings.find((f) => f.discoveredApps?.length)!;
      assert.match(finding.description, /recreated registration/);
      assert.match(finding.description, /eeeeeeee-0000-0000-0000-000000000005/);
      assert.match(finding.description, /44444444-4444-4444-4444-444444444444/);
    },
  ],
  [
    "name matching is exact once normalized - it never conflates separate apps",
    () => {
      const index = new Map([
        [
          "fixture app",
          [{ appId: "44444444-4444-4444-4444-444444444444", displayName: "Fixture App" }],
        ],
      ]);
      // Case and separator differences are the same app
      assert.equal(
        findNameMatchedServicePrincipals("FIXTURE-APP", "eeee", index).length,
        1
      );
      // A prefixed variant is a DIFFERENT app, never a match
      assert.equal(
        findNameMatchedServicePrincipals("Test-Fixture App", "eeee", index).length,
        0
      );
      // The service principal's own app never matches itself
      assert.equal(
        findNameMatchedServicePrincipals(
          "Fixture App",
          "44444444-4444-4444-4444-444444444444",
          index
        ).length,
        0
      );
      assert.equal(findNameMatchedServicePrincipals(undefined, "eeee", index).length, 0);
    },
  ],
  [
    "classifier: absent or unreadable evidence is never treated as coverage",
    () => {
      assert.equal(classifyObservedCoverage(undefined, undefined), "unknown");
      assert.equal(classifyObservedCoverage("notApplied", []), "unknown");
      assert.equal(classifyObservedCoverage("unknownFutureValue", []), "unknown");
      assert.equal(
        classifyObservedCoverage("notApplied", [{ conditionsNotSatisfied: "" }]),
        "unknown"
      );
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
