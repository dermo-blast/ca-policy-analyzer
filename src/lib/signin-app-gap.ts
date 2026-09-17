// Discovered apps -> findings + a PowerShell script to register them. Pure and
// synchronous; every Graph call already happened during context load.

import { TenantContext, UnregisteredSignInApp } from "./graph-client";
import { DiscoveredAppDetail, Finding, Severity } from "./analyzer";
import {
  PolicyAppImpact,
  evaluateAppImpact,
  wouldBlock,
} from "./policy-app-impact";
import { TemplateAnalysisResult } from "./template-matcher";
import { APP_DESCRIPTION_MAP } from "@/data/app-descriptions";
import { CA_BYPASS_APPS, WELL_KNOWN_APP_MAP } from "@/data/ca-bypass-database";
import { getFociApp, getFociFamily } from "@/data/foci-families";
import { getFirstPartyAppName } from "@/data/first-party-apps";

export const SIGNIN_APP_GAP_CATEGORY = "Missing Service Principals";

export interface SignInAppGapSummary {
  total: number;
  wouldBlock: number;
  wouldEnforce: number;
  mayApply: number;
  phantomExclusions: number;
  knownBypass: number;
  stillUncovered: number;
  /** Apps whose evidence sign-in shows Conditional Access already evaluated them. */
  observedCovered: number;
  /** Apps whose name matches an existing service principal with a different appId. */
  nameMatchedExisting: number;
}

/**
 * Service principals indexed by normalized display name.
 *
 * Only an exact (normalized) match counts. An app registration that was deleted
 * and recreated keeps its display name and gets a new appId - that is the case
 * worth reporting, because a policy scoped to the service principal an admin
 * can see will not match the appId that is actually signing in. Fuzzy matching
 * would conflate genuinely separate apps: "Test-Foo" and "Foo" are two apps,
 * not one recreated twice.
 */
function normalizeAppName(name: string | undefined): string {
  return (name ?? "")
    .toLowerCase()
    .replace(/[-_]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export interface NameMatchedServicePrincipal {
  appId: string;
  displayName: string;
}

function buildServicePrincipalNameIndex(
  context: TenantContext
): Map<string, NameMatchedServicePrincipal[]> {
  const byName = new Map<string, NameMatchedServicePrincipal[]>();
  for (const sp of context.servicePrincipals.values()) {
    const key = normalizeAppName(sp.displayName);
    if (!key) continue;
    const list = byName.get(key) ?? [];
    list.push({ appId: sp.appId, displayName: sp.displayName });
    byName.set(key, list);
  }
  return byName;
}

export function findNameMatchedServicePrincipals(
  displayName: string | undefined,
  appId: string,
  index: Map<string, NameMatchedServicePrincipal[]>
): NameMatchedServicePrincipal[] {
  const key = normalizeAppName(displayName);
  if (!key) return [];
  return (index.get(key) ?? []).filter(
    (sp) => sp.appId.toLowerCase() !== appId.toLowerCase()
  );
}

/**
 * What the app's own evidence sign-in says about Conditional Access reaching it.
 *
 *  - `covered`        Entra evaluated CA and reached a verdict, so the app is in
 *                     policy scope today. A policy targeting All resources reaches
 *                     apps that can't be named in the picker, so "no service
 *                     principal" does not imply "no policy applies".
 *  - `userOutOfScope` A policy matched the application but not the user, so the
 *                     sampled sign-in was an excluded account - evidence about
 *                     that user, not about the app being unreachable.
 *  - `appUnmatched`   Every policy that ran failed on the application condition:
 *                     the app itself is what no policy matched.
 *  - `unknown`        No evidence row, or nothing conclusive in it.
 */
export type ObservedCoverage =
  | "covered"
  | "userOutOfScope"
  | "appUnmatched"
  | "unknown";

function conditionList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function classifyObservedCoverage(
  conditionalAccessStatus: string | undefined,
  policies: ReadonlyArray<{ conditionsNotSatisfied?: string }> | undefined
): ObservedCoverage {
  const status = conditionalAccessStatus?.trim().toLowerCase();
  if (!status) return "unknown";
  // "failure" still means CA applied - the user just didn't satisfy it.
  if (status === "success" || status === "failure") return "covered";
  if (status !== "notapplied") return "unknown";

  const evaluated = policies ?? [];
  if (evaluated.length === 0) return "unknown";

  // A policy that satisfied the application condition but not the user proves
  // the app is reachable by policy - the sampled account was simply excluded.
  const matchedAppNotUser = evaluated.some((p) => {
    const missing = conditionList(p.conditionsNotSatisfied);
    return missing.includes("users") && !missing.includes("application");
  });
  if (matchedAppNotUser) return "userOutOfScope";

  const everyPolicyMissedTheApp = evaluated.every((p) =>
    conditionList(p.conditionsNotSatisfied).includes("application")
  );
  if (everyPolicyMissedTheApp) return "appUnmatched";

  return "unknown";
}

export interface SignInAppGapResult {
  findings: Finding[];
  apps: DiscoveredAppDetail[];
  summary: SignInAppGapSummary;
  truncated: boolean;
  evidenceCapped: number;
  scanUnavailable: boolean;
}

const CA_BYPASS_APP_MAP = new Map(
  CA_BYPASS_APPS.map((a) => [a.appId.toLowerCase(), a])
);

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

let gapFindingCounter = 0;
function nextGapFindingId(): string {
  return `SIA-${String(++gapFindingCounter).padStart(4, "0")}`;
}

// ─── Name resolution ─────────────────────────────────────────────────────────

function resolveDisplayName(app: UnregisteredSignInApp): string {
  if (app.displayName) return app.displayName;
  const id = app.appId.toLowerCase();
  return (
    APP_DESCRIPTION_MAP.get(id)?.displayName ??
    WELL_KNOWN_APP_MAP.get(id)?.displayName ??
    getFociApp(id)?.displayName ??
    getFirstPartyAppName(id) ??
    "Unknown app"
  );
}

// ─── Cross-references ────────────────────────────────────────────────────────

function buildBypassNote(appId: string): string | undefined {
  const id = appId.toLowerCase();

  const bypass = CA_BYPASS_APP_MAP.get(id);
  if (bypass) {
    return (
      `Documented Conditional Access bypass app: ${bypass.description}` +
      (bypass.isPublicClient ? " It is a public client, so it can never be targeted individually - only All resources reaches it." : "")
    );
  }

  const foci = getFociApp(id);
  if (foci) {
    const family = getFociFamily(id);
    return (
      `FOCI family member (${foci.description}). Its refresh tokens are interchangeable with ` +
      `${family.length} other apps, so a token issued here can be redeemed elsewhere in the family.`
    );
  }

  return undefined;
}

function buildBaselineNote(
  appId: string,
  templateResult?: TemplateAnalysisResult
): string | undefined {
  if (!templateResult) return undefined;
  const id = appId.toLowerCase();
  const hits: string[] = [];

  for (const match of templateResult.matches) {
    const tpl = match.template;
    const fingerprintApps = (tpl.fingerprint.includeApps ?? []).map((a) =>
      a.toLowerCase()
    );
    const deployApps = tpl.deploymentJson?.conditions?.applications;
    const deployIds = [
      ...(deployApps?.includeApplications ?? []),
      ...(deployApps?.excludeApplications ?? []),
    ].map((a) => a.toLowerCase());

    if (fingerprintApps.includes(id) || deployIds.includes(id)) {
      hits.push(tpl.displayName);
    }
  }

  if (hits.length === 0) return undefined;
  return (
    `Your baseline references this app by ID in ${hits.length} template(s): ` +
    `${hits.slice(0, 3).join(", ")}${hits.length > 3 ? `, +${hits.length - 3} more` : ""}. ` +
    "The baseline assumes the app exists in the tenant."
  );
}

// ─── Severity ────────────────────────────────────────────────────────────────

function gradeApp(
  app: UnregisteredSignInApp,
  impact: PolicyAppImpact[],
  bypassNote: string | undefined,
  phantomExclusionPolicies: string[]
): Severity {
  if (bypassNote) return "critical";
  if (phantomExclusionPolicies.length > 0) return "critical";

  // Observed evidence outranks predicted impact. The rest of this function
  // grades what *would* happen once a service principal exists; if Entra has
  // already evaluated Conditional Access for this app, that prediction is not
  // a security gap, and grading it critical contradicts the evidence stored on
  // the finding itself.
  const coverage = classifyObservedCoverage(
    app.conditionalAccessStatus,
    app.appliedPolicies
  );
  if (coverage === "covered") return "info";
  if (coverage === "userOutOfScope") return "low";

  if (impact.some(wouldBlock)) return "critical";

  const enabledWillApply = impact.some(
    (i) => i.state === "enabled" && i.verdict === "willApply"
  );
  if (app.seenIn === "Interactive" && enabledWillApply) return "high";
  if (enabledWillApply) return "medium";
  if (impact.some((i) => i.state === "enabled" && i.verdict === "mayApply")) {
    return "medium";
  }
  return "info";
}

function highestSeverity(apps: DiscoveredAppDetail[]): Severity {
  return apps.reduce<Severity>(
    (worst, app) =>
      SEVERITY_RANK[app.severity] < SEVERITY_RANK[worst] ? app.severity : worst,
    "info"
  );
}

// ─── Main analyzer ───────────────────────────────────────────────────────────

export function analyzeSignInAppGap(
  context: TenantContext,
  templateResult?: TemplateAnalysisResult
): SignInAppGapResult {
  gapFindingCounter = 0;
  const scan = context.unregisteredSignInApps;

  if (!scan) {
    return {
      findings: [
        {
          id: nextGapFindingId(),
          policyId: "tenant-wide",
          policyName: "Tenant-Wide Analysis",
          severity: "info",
          category: SIGNIN_APP_GAP_CATEGORY,
          title: "Sign-in log scan for unregistered service principals was not available",
          description:
            "This check compares the apps in your sign-in logs against the service principals " +
            "in your tenant. An app with no service principal cannot be selected in a Conditional " +
            "Access policy at all - it can be neither included nor excluded - so it sits outside " +
            "your policies without appearing anywhere as a gap. No sign-in data was available " +
            "for this run.",
          recommendation:
            "For a live tenant connection, switch the \"Scan sign-in logs\" option on and re-scan. " +
            "It needs AuditLog.Read.All (admin consent) and Entra ID P1 or higher, since sign-in " +
            "logs are a P1 feature. For offline mode, re-run the export script from the Offline " +
            "Export Guide - the sign-in app dataset was added to it and older exports don't " +
            "contain it.",
        },
      ],
      apps: [],
      summary: {
        total: 0,
        wouldBlock: 0,
        wouldEnforce: 0,
        mayApply: 0,
        phantomExclusions: 0,
        knownBypass: 0,
        stillUncovered: 0,
        observedCovered: 0,
        nameMatchedExisting: 0,
      },
      truncated: false,
      evidenceCapped: 0,
      scanUnavailable: true,
    };
  }

  // An app whose display name matches a service principal that already exists
  // under a DIFFERENT appId is usually a registration that was recreated. Worth
  // saying out loud: an admin looking at Enterprise applications sees the name
  // and assumes it is covered, but a policy scoped to that service principal
  // does not match the appId actually signing in.
  const nameIndex = buildServicePrincipalNameIndex(context);

  const apps: DiscoveredAppDetail[] = scan.apps.map((app) => {
    const impact = evaluateAppImpact(
      {
        appId: app.appId,
        clientAppUsed: app.clientAppUsed,
        userPrincipalName: app.userPrincipalName,
        isWorkloadIdentity: app.isWorkloadIdentity,
      },
      context
    );

    const phantomExclusionPolicies = impact
      .filter((i) => i.phantomExclusion)
      .map((i) => i.policyName);
    const bypassNote = buildBypassNote(app.appId);
    const displayName = resolveDisplayName(app);
    const nameMatchedServicePrincipals = findNameMatchedServicePrincipals(
      displayName,
      app.appId,
      nameIndex
    );

    return {
      appId: app.appId,
      displayName,
      signInCount: app.signInCount,
      seenIn: app.seenIn,
      lastSeen: app.lastSeen,
      requestId: app.requestId,
      userPrincipalName: app.userPrincipalName,
      ipAddress: app.ipAddress,
      clientAppUsed: app.clientAppUsed,
      resourceDisplayName: app.resourceDisplayName,
      conditionalAccessStatus: app.conditionalAccessStatus,
      isWorkloadIdentity: app.isWorkloadIdentity,
      logQueryUrl: app.logQueryUrl,
      observedPolicies: app.appliedPolicies,
      predictedImpact: impact,
      severity: gradeApp(app, impact, bypassNote, phantomExclusionPolicies),
      bypassNote,
      baselineNote: buildBaselineNote(app.appId, templateResult),
      phantomExclusionPolicies,
      evidenceMissing: !app.lastSeen,
      nameMatchedServicePrincipals: nameMatchedServicePrincipals.length
        ? nameMatchedServicePrincipals
        : undefined,
    };
  });

  const nameMatched = apps.filter((a) => a.nameMatchedServicePrincipals?.length);

  const summary: SignInAppGapSummary = {
    total: apps.length,
    wouldBlock: apps.filter((a) => a.predictedImpact.some(wouldBlock)).length,
    wouldEnforce: apps.filter((a) =>
      a.predictedImpact.some(
        (i) => i.state === "enabled" && i.verdict === "willApply" && !i.blocks
      )
    ).length,
    mayApply: apps.filter((a) =>
      a.predictedImpact.some(
        (i) => i.state === "enabled" && i.verdict === "mayApply"
      )
    ).length,
    phantomExclusions: apps.filter((a) => a.phantomExclusionPolicies.length > 0)
      .length,
    knownBypass: apps.filter((a) => a.bypassNote).length,
    stillUncovered: apps.filter(
      (a) =>
        !a.predictedImpact.some(
          (i) => i.state === "enabled" && i.verdict !== "willNotApply"
        )
    ).length,
    observedCovered: apps.filter(
      (a) =>
        classifyObservedCoverage(a.conditionalAccessStatus, a.observedPolicies) ===
        "covered"
    ).length,
    nameMatchedExisting: nameMatched.length,
  };

  const findings: Finding[] = [];

  if (apps.length > 0) {
    const notes: string[] = [];
    if (scan.truncated) {
      notes.push(
        "The discovery endpoint returned its maximum of 1000 apps, so this list may be incomplete."
      );
    }
    if (scan.evidenceCapped > 0) {
      notes.push(
        `${scan.evidenceCapped} app(s) are listed by ID and sign-in count only - evidence lookups ` +
          "are capped at the 60 busiest apps."
      );
    }
    if (summary.stillUncovered > 0) {
      notes.push(
        `${summary.stillUncovered} of these apps would still not be reached by any enabled policy ` +
          "even after you create the service principal - check whether a policy targeting All resources exists."
      );
    }
    // The name-collision detail is deliberately NOT appended here - it renders
    // as its own callout beside the app list, where the apps it refers to are.
    if (summary.observedCovered > 0) {
      notes.push(
        `${summary.observedCovered} of these apps were already evaluated by Conditional Access on ` +
          "their most recent sign-in, so policy reaches them today - a policy targeting All resources " +
          "covers apps that cannot be named in the picker. For those, creating the service principal " +
          "buys the ability to target or exclude them individually, not new coverage."
      );
    }

    findings.push({
      id: nextGapFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: highestSeverity(apps),
      category: SIGNIN_APP_GAP_CATEGORY,
      title: `${apps.length} enterprise app(s) signed in over the last 30 days but have no service principal`,
      description:
        `${apps.length} app(s) signed in over the last 30 days with no service principal in this ` +
        "tenant. Without one they are absent from the Conditional Access app picker: you cannot " +
        "target them in a policy, and you cannot exclude them from one either. App protection " +
        "policies and Global Secure Access cannot reach them at all. " +
        notes.join(" "),
      recommendation:
        "Check each app against its impact preview, then create the missing service principals " +
        "with the generated script.",
      relatedIds: apps.map((a) => a.appId),
      discoveredApps: apps,
    });
  }

  const bypassApps = apps.filter((a) => a.bypassNote);
  if (bypassApps.length > 0) {
    findings.push({
      id: nextGapFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "critical",
      category: SIGNIN_APP_GAP_CATEGORY,
      title: `${bypassApps.length} of the unregistered service principal(s) are documented Conditional Access bypass apps`,
      description:
        `${bypassApps.map((a) => a.displayName).join(", ")} - these are in the known CA-bypass or ` +
        "FOCI token-sharing databases and have no service principal in this tenant. That is the worst " +
        "combination: the app is a documented route around Conditional Access, and you currently cannot " +
        "write a policy that names it. Full detail for each is in the app list above.",
      recommendation:
        "Create the service principal for each of these first so the app becomes targetable, then " +
        "confirm it is covered by a policy that requires phishing-resistant MFA or blocks the app " +
        "outright where it has no business use.",
      relatedIds: bypassApps.map((a) => a.appId),
    });
  }

  const phantomApps = apps.filter((a) => a.phantomExclusionPolicies.length > 0);
  if (phantomApps.length > 0) {
    findings.push({
      id: nextGapFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "critical",
      category: SIGNIN_APP_GAP_CATEGORY,
      title: `${phantomApps.length} policy exclusion(s) point at an app that does not exist`,
      description:
        phantomApps
          .map(
            (a) =>
              `"${a.displayName}" is excluded by ${a.phantomExclusionPolicies.join(" and ")}`
          )
          .join("; ") +
        ". Each of these apps has no service principal, so the exclusion does nothing - which also " +
        "means nobody has noticed the app was never in scope to begin with. If the app is created " +
        "later, the exclusion silently becomes live.",
      recommendation:
        "Decide deliberately for each one: if the exclusion is still wanted, create the service " +
        "principal so the exclusion is real and reviewable. If it is not, remove the stale exclusion " +
        "so the policy stops carrying a hole nobody is tracking.",
      relatedIds: phantomApps.map((a) => a.appId),
    });
  }

  return {
    findings,
    apps,
    summary,
    truncated: scan.truncated,
    evidenceCapped: scan.evidenceCapped,
    scanUnavailable: false,
  };
}

// ─── PowerShell generator ────────────────────────────────────────────────────

/** Single-quoted PowerShell string literal - doubles any embedded quote. */
function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export function buildCreateServicePrincipalsScript(
  apps: DiscoveredAppDetail[],
  options: { tenantDisplayName?: string; tenantId?: string; generatedAt?: string } = {}
): string {
  const stamp = options.generatedAt ?? new Date().toISOString();
  const blockedCount = apps.filter((a) => a.predictedImpact.some(wouldBlock)).length;

  const lines: string[] = [];

  lines.push("<#");
  lines.push("    Register missing Entra ID enterprise applications (service principals)");
  lines.push("");
  lines.push("    Generated by CA Policy Analyzer");
  lines.push(`    Generated on : ${stamp}`);
  if (options.tenantDisplayName) {
    lines.push(
      `    Tenant       : ${options.tenantDisplayName}${options.tenantId ? ` (${options.tenantId})` : ""}`
    );
  }
  lines.push(`    Apps found   : ${apps.length}${blockedCount > 0 ? ` (${blockedCount} would be blocked)` : ""}`);
  lines.push("");
  lines.push("    READ THIS FIRST");
  lines.push("");
  lines.push("    Each app in $appsToCreate appeared in your sign-in logs over the last 30 days");
  lines.push("    but has no service principal in this tenant. Without one it cannot be selected");
  lines.push("    in a Conditional Access policy at all, so it is neither included nor excluded.");
  lines.push("");
  lines.push("    Creating the service principal makes the app visible to Entra ID. From that");
  lines.push("    moment every policy that includes All resources starts applying to it. Sign-ins");
  lines.push("    that succeed today can begin failing.");
  lines.push("");
  lines.push("    Run with -WhatIf first. Create in waves, not all at once.");
  if (blockedCount > 0) {
    lines.push("");
    lines.push(`    ${blockedCount} app(s) below are marked "BLOCKED BY": an enabled block policy`);
    lines.push("    would catch them the instant their service principal exists. Add an exclusion");
    lines.push("    or move that policy to report-only first, or delete those lines from");
    lines.push("    $appsToCreate to leave them for later.");
  }
  lines.push("");
  lines.push("    Requires: Microsoft.Graph.Authentication, Application.ReadWrite.All");
  lines.push("");
  lines.push("    .EXAMPLE");
  lines.push("        .\\Register-MissingServicePrincipals.ps1 -WhatIf");
  lines.push("    .EXAMPLE");
  lines.push("        .\\Register-MissingServicePrincipals.ps1");
  lines.push("#>");
  lines.push("");
  lines.push("[CmdletBinding(SupportsShouldProcess)]");
  lines.push("param(");
  lines.push("    [string]$TenantId");
  lines.push(")");
  lines.push("");
  lines.push("Import-Module Microsoft.Graph.Authentication -ErrorAction Stop");
  lines.push("");
  lines.push("$connectParams = @{ Scopes = 'Application.ReadWrite.All'; NoWelcome = $true; ErrorAction = 'Stop' }");
  lines.push("if ($TenantId) { $connectParams.TenantId = $TenantId }");
  lines.push("Connect-MgGraph @connectParams");
  lines.push("");
  lines.push("$graphBase = 'https://graph.microsoft.com/v1.0'");
  lines.push("");
  lines.push("# Every app found in the sign-in logs without a service principal.");
  lines.push("$appsToCreate = @(");

  if (apps.length === 0) {
    lines.push("    # Nothing found - no unregistered service principals in the last 30 days of sign-in logs.");
  }
  for (const app of apps) {
    const blockers = app.predictedImpact
      .filter(wouldBlock)
      .map((i) => i.policyName)
      .join("; ");
    lines.push(
      "    @{ AppId = " +
        psQuote(app.appId) +
        "; Name = " +
        psQuote(app.displayName) +
        " }" +
        (blockers ? `   # BLOCKED BY: ${blockers}` : "")
    );
  }

  lines.push(")");
  lines.push("");
  lines.push("Write-Host \"Processing $($appsToCreate.Count) app(s)\" -ForegroundColor Cyan");
  lines.push("Write-Host ''");
  lines.push("");
  lines.push("$created = 0; $existing = 0; $skipped = 0; $failed = 0");
  lines.push("$results = [System.Collections.Generic.List[pscustomobject]]::new()");
  lines.push("");
  lines.push("foreach ($app in $appsToCreate) {");
  lines.push("    try {");
  lines.push("        $filter = [uri]::EscapeDataString(\"appId eq '$($app.AppId)'\")");
  lines.push("        $lookup = Invoke-MgGraphRequest -Method GET \`");
  lines.push("            -Uri \"$graphBase/servicePrincipals?`$filter=$filter&`$select=id,appId,displayName\" \`");
  lines.push("            -ErrorAction Stop");
  lines.push("");
  lines.push("        if (@($lookup.value).Count -gt 0) {");
  lines.push("            Write-Host \"[OK]      $($app.Name) already exists\" -ForegroundColor DarkGray -NoNewline");
  lines.push("            Write-Host \" [$($app.AppId)]\" -ForegroundColor DarkGray");
  lines.push("            $existing++");
  lines.push("            $results.Add([pscustomobject]@{ AppId = $app.AppId; Name = $app.Name; Status = 'AlreadyExisting'; Detail = $null })");
  lines.push("            continue");
  lines.push("        }");
  lines.push("");
  lines.push("        if ($PSCmdlet.ShouldProcess(\"$($app.Name) [$($app.AppId)]\", 'Create service principal')) {");
  lines.push("            $new = Invoke-MgGraphRequest -Method POST \`");
  lines.push("                -Uri \"$graphBase/servicePrincipals\" \`");
  lines.push("                -Body @{ appId = $app.AppId } \`");
  lines.push("                -ContentType 'application/json' \`");
  lines.push("                -ErrorAction Stop");
  lines.push("");
  lines.push("            Write-Host \"[CREATED] $($new.displayName)\" -ForegroundColor Green -NoNewline");
  lines.push("            Write-Host \" [$($app.AppId)]\" -ForegroundColor DarkGray");
  lines.push("            $created++");
  lines.push("            $results.Add([pscustomobject]@{ AppId = $app.AppId; Name = $new.displayName; Status = 'Created' })");
  lines.push("        }");
  lines.push("    }");
  lines.push("    catch {");
  lines.push("        $message = $_.Exception.Message");
  lines.push("        if ($message -match 'does not reference a valid application object' -or");
  lines.push("            $message -match 'Request_BadRequest') {");
  lines.push("            # Some Microsoft first-party app IDs cannot be instantiated in a tenant");
  lines.push("            Write-Host \"[SKIP]    $($app.Name) cannot be instantiated\" -ForegroundColor Yellow -NoNewline");
  lines.push("            Write-Host \" [$($app.AppId)]\" -ForegroundColor DarkYellow");
  lines.push("            $skipped++");
  lines.push("            $results.Add([pscustomobject]@{ AppId = $app.AppId; Name = $app.Name; Status = 'Skipped'; Detail = $message })");
  lines.push("        }");
  lines.push("        elseif ($message -match 'already in use' -or");
  lines.push("                $message -match 'MultipleObjectsWithSameKeyValue') {");
  lines.push("            # 409 - created by a parallel run between the lookup and the POST");
  lines.push("            Write-Host \"[OK]      $($app.Name) already exists\" -ForegroundColor DarkGray -NoNewline");
  lines.push("            Write-Host \" [$($app.AppId)]\" -ForegroundColor DarkGray");
  lines.push("            $existing++");
  lines.push("            $results.Add([pscustomobject]@{ AppId = $app.AppId; Name = $app.Name; Status = 'AlreadyExisting'; Detail = $null })");
  lines.push("        }");
  lines.push("        else {");
  lines.push("            Write-Host \"[ERROR]   $($app.Name)\" -ForegroundColor Red -NoNewline");
  lines.push("            Write-Host \" [$($app.AppId)]: $message\" -ForegroundColor DarkRed");
  lines.push("            $failed++");
  lines.push("            $results.Add([pscustomobject]@{ AppId = $app.AppId; Name = $app.Name; Status = 'Failed'; Detail = $message })");
  lines.push("        }");
  lines.push("    }");
  lines.push("}");
  lines.push("");
  lines.push("Write-Host ''");
  lines.push("Write-Host \"Created: $created  Already existing: $existing  Skipped: $skipped  Failed: $failed\" -ForegroundColor Cyan");
  lines.push("if ($created -gt 0) {");
  lines.push("    Write-Host 'Watch your sign-in logs for newly blocked sign-ins over the next 24 hours.' -ForegroundColor Yellow");
  lines.push("}");
  lines.push("");
  lines.push("# Uncomment to keep a record of what this run did");
  lines.push("# $results | Export-Csv -Path './service-principal-run.csv' -NoTypeInformation -Encoding UTF8");
  lines.push("");
  return lines.join("\n");
}

