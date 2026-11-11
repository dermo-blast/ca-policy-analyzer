"use client";

import { PolicyResult, Finding, ExcludedAppDetail } from "@/lib/analyzer";
import { PolicySignInLogResult, PolicySignInMatch, buildPolicySignInLogQueryUrl, buildSignInMatchLogQueryUrl } from "@/lib/graph-client";
import { SeverityBadge, Card } from "./ui-primitives";
import { cn } from "@/lib/utils";
import { resolveRoleList, resolveGuidList, type GuidResolverMaps } from "@/lib/role-names";
import { describeGuestsOrExternalUsers } from "@/lib/condition-labels";
import {
  Users,
  Cloud,
  Filter,
  ShieldCheck,
  Clock,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  Info,
  ShieldAlert,
  Search,
  X,
  History,
  ExternalLink,
} from "lucide-react";
import { useState } from "react";

function PolicyFlowSection({
  icon: Icon,
  label,
  items,
  emptyText = "None",
}: {
  icon: typeof Users;
  label: string;
  items: string[];
  emptyText?: string;
}) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-gray-500" />
      <div>
        <p className="text-xs font-medium text-gray-400">{label}</p>
        {items.length > 0 ? (
          <ul className="mt-0.5">
            {items.map((item, i) => (
              <li key={i} className="text-sm text-gray-300">
                {item}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-gray-600">{emptyText}</p>
        )}
      </div>
    </div>
  );
}

// ─── Risk badge for excluded app details ─────────────────────────────────────

function RiskBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10 text-red-400",
    high: "bg-orange-500/10 text-orange-400",
    medium: "bg-yellow-500/10 text-yellow-400",
    low: "bg-gray-800 text-gray-400",
  };
  return (
    <span className={cn("text-[10px] font-medium rounded px-1.5 py-0.5 uppercase", colors[risk] ?? colors.low)}>
      {risk} risk
    </span>
  );
}

// ─── Single excluded app detail card ─────────────────────────────────────────

function ExcludedAppCard({ app }: { app: ExcludedAppDetail }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-white">{app.displayName}</span>
        <RiskBadge risk={app.risk} />
      </div>
      <div className="space-y-1">
        <div>
          <span className="text-[10px] font-medium uppercase text-gray-600">What it does</span>
          <p className="text-xs text-gray-400">{app.purpose}</p>
        </div>
        <div>
          <span className="text-[10px] font-medium uppercase text-gray-600">Why it&apos;s excluded</span>
          <p className="text-xs text-gray-400">{app.exclusionReason}</p>
        </div>
      </div>
      <p className="text-[10px] text-gray-700 font-mono">{app.appId}</p>
    </div>
  );
}

// ─── Collapsible finding row ─────────────────────────────────────────────────

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const hasDetails = finding.excludedApps && finding.excludedApps.length > 0;

  return (
    <div className="rounded-lg bg-gray-950/50 overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-start gap-2 p-3 text-left hover:bg-gray-950/80 transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-gray-300">{finding.title}</p>
          {!open && (
            <p className="mt-0.5 text-xs text-gray-500 line-clamp-2">
              {finding.description}
            </p>
          )}
        </div>
        <div className="shrink-0 mt-0.5">
          {open ? (
            <ChevronDown className="h-4 w-4 text-gray-600" />
          ) : (
            <ChevronRight className="h-4 w-4 text-gray-600" />
          )}
        </div>
      </button>

      {open && (
        <div className="border-t border-gray-800/50 p-3 space-y-3">
          <p className="text-xs text-gray-400">{finding.description}</p>

          {/* Recommendation */}
          <div className="flex items-start gap-2 rounded-md bg-blue-500/5 border border-blue-500/10 p-2">
            <Info className="h-3.5 w-3.5 shrink-0 mt-0.5 text-blue-400" />
            <p className="text-xs text-blue-300">{finding.recommendation}</p>
          </div>

          {/* Excluded app details with per-app descriptions */}
          {hasDetails && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-gray-500" />
                <span className="text-[10px] font-medium uppercase text-gray-500">
                  Excluded apps ({finding.excludedApps!.length})
                </span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {finding.excludedApps!.map((app) => (
                  <ExcludedAppCard key={app.appId} app={app} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Group findings by severity ──────────────────────────────────────────────

type SeverityGroup = { severity: string; label: string; findings: Finding[]; color: string };

function FindingsGrouped({ findings }: { findings: Finding[] }) {
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set(["critical", "high"]));

  const groups: SeverityGroup[] = [
    { severity: "critical", label: "Critical", findings: [], color: "text-red-400" },
    { severity: "high", label: "High", findings: [], color: "text-orange-400" },
    { severity: "medium", label: "Medium", findings: [], color: "text-yellow-400" },
    { severity: "low", label: "Low", findings: [], color: "text-gray-400" },
    { severity: "info", label: "Info", findings: [], color: "text-blue-400" },
  ];

  for (const f of findings) {
    const g = groups.find((g) => g.severity === f.severity);
    if (g) g.findings.push(f);
  }

  const nonEmpty = groups.filter((g) => g.findings.length > 0);

  // If 3 or fewer total findings, just show them flat (no grouping needed)
  if (findings.length <= 3) {
    return (
      <div className="space-y-2">
        {findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </div>
    );
  }

  const toggle = (sev: string) => {
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };

  return (
    <div className="space-y-1.5">
      {nonEmpty.map((g) => (
        <div key={g.severity}>
          <button
            onClick={() => toggle(g.severity)}
            className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-gray-950/50 transition-colors"
          >
            {openGroups.has(g.severity) ? (
              <ChevronDown className="h-3.5 w-3.5 text-gray-600" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-gray-600" />
            )}
            <span className={cn("text-xs font-medium", g.color)}>
              {g.label}
            </span>
            <span className="text-xs text-gray-600">
              ({g.findings.length})
            </span>
          </button>
          {openGroups.has(g.severity) && (
            <div className="ml-2 space-y-1.5 mt-1">
              {g.findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function PolicySignInMatchesSection({ policyId, policyName, result }: { policyId: string; policyName: string; result?: PolicySignInLogResult }) {
  // Default collapsed when there's nothing to see - most policies in a
  // healthy tenant show "0 in last 30 days", and expanding all of them by
  // default made cards taller than they needed to be. Policies that DID
  // catch something (blocked/would-block matches) still open by default so
  // the finding is visible without an extra click.
  const hasAnyMatches = (result?.byPolicy.get(policyId)?.matches.length ?? 0) > 0;
  const [open, setOpen] = useState(hasAnyMatches);

  // Sign-in log scan wasn't run for this analysis (no AuditLog.Read.All / P1,
  // or an offline export that predates this dataset).
  if (!result) {
    return (
      <div className="mt-4 border-t border-gray-800 pt-4">
        <div className="flex items-start gap-2 rounded-lg border border-dashed border-gray-700 px-3 py-2.5 text-xs text-gray-500">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Sign-in log matches not scanned — turn on{" "}
            <strong className="text-gray-400">Scan sign-in logs</strong> and
            re-run the analysis to see this.
          </span>
        </div>
      </div>
    );
  }

  const entry = result.byPolicy.get(policyId);
  const matches = entry?.matches ?? [];
  const blockedCount = matches.filter((m) => m.status === "blocked").length;
  const wouldBlockCount = matches.filter((m) => m.status === "wouldBlock").length;
  const totalCount = matches.length;

  // The scan already caps matches per policy (POLICY_SIGNIN_MATCHES_PER_POLICY_CAP
  // = 25), and this trims the inline view further so a noisy policy doesn't
  // dominate the card - "view the rest in the sign-in logs" covers the gap.
  const VISIBLE_MATCHES_LIMIT = 10;
  const visibleMatches = matches.slice(0, VISIBLE_MATCHES_LIMIT);
  const hiddenCount = totalCount - visibleMatches.length;
  const hasMoreToSee = hiddenCount > 0 || entry?.truncated;
  const logQueryUrl = buildPolicySignInLogQueryUrl(policyName, result.windowStart);

  return (
    <div className="mt-4 border-t border-gray-800 pt-4">
      <button
        onClick={() => setOpen(!open)}
        className={cn(
          "flex w-full items-center justify-between rounded-lg border px-3 py-2.5 text-left transition-colors",
          "border-gray-700 bg-gray-800/60 hover:bg-gray-800"
        )}
      >
        <div className="flex items-center gap-2 text-xs font-semibold text-gray-200">
          <History className="h-3.5 w-3.5 text-gray-400" />
          Sign-in log matches
          {totalCount > 0 ? (
            <span
              className={cn(
                "rounded-full px-2 py-0.5 text-[11px] font-bold",
                blockedCount > 0
                  ? "bg-red-500/15 text-red-400"
                  : "bg-amber-500/15 text-amber-400"
              )}
            >
              {blockedCount > 0
                ? `${blockedCount} blocked`
                : `${wouldBlockCount} would be blocked`}
            </span>
          ) : (
            <span className="rounded-full bg-green-500/10 px-2 py-0.5 text-[11px] font-bold text-green-400">
              0 in last 30 days
            </span>
          )}
        </div>
        {open ? (
          <ChevronDown className="h-4 w-4 text-gray-500" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-500" />
        )}
      </button>

      {open && (
        <div className="mt-2">
          {totalCount === 0 ? (
            <div className="rounded-lg border border-gray-800 py-4 text-center">
              <p className="text-xs italic text-gray-600">
                No blocked or report-only-flagged sign-ins found for this policy in the last 30 days.
              </p>
              {result.scanError ? (
                <p className="mt-1.5 px-3 text-[11px] text-amber-500">
                  The scan hit an error and stopped early - this result may be incomplete: {result.scanError}
                </p>
              ) : result.rowsScanned > 0 && result.rowsMissingCaData === result.rowsScanned ? (
                <p className="mt-1.5 px-3 text-[11px] text-amber-500">
                  Scanned {result.rowsScanned} sign-in{result.rowsScanned !== 1 ? "s" : ""}, but none included Conditional Access data -
                  the signed-in account may be missing the Entra role needed to read it (Global Reader, Security Reader,
                  Security Administrator, or Conditional Access Administrator). This affects every policy, not just this one.
                </p>
              ) : result.rowsScanned === 0 ? (
                <p className="mt-1.5 px-3 text-[11px] text-gray-600">
                  No sign-ins at all were returned for the last 30 days - if you expect activity, check the account still has
                  AuditLog.Read.All consent and try again.
                </p>
              ) : null}
            </div>
          ) : (
            <>
              <p className="mb-2 px-1 text-[11px] text-gray-500">
                Last 30 days · <strong className="text-gray-400">{totalCount}</strong> matching sign-in{totalCount !== 1 ? "s" : ""}
                {hiddenCount > 0 ? ` · showing first ${visibleMatches.length}` : ""}
                {entry?.truncated ? " (sample - more exist beyond the scan cap)" : ""}
              </p>
              <div className="overflow-x-auto rounded-lg border border-gray-800">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-gray-800 bg-gray-900/50 text-left text-gray-500">
                      <th className="px-3 py-1.5 font-medium">User</th>
                      <th className="px-3 py-1.5 font-medium">Date / Time</th>
                      <th className="px-3 py-1.5 font-medium">Location</th>
                      <th className="px-3 py-1.5 font-medium">Client App</th>
                      <th className="px-3 py-1.5 font-medium">Status</th>
                      <th className="px-3 py-1.5 font-medium">Failure Reason</th>
                      <th className="px-3 py-1.5 font-medium">
                        <span className="sr-only">View in Graph Explorer</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleMatches.map((m) => (
                      <SignInMatchRow key={m.id} match={m} fallbackLogQueryUrl={logQueryUrl} />
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {hasMoreToSee && (
            <a
              href={logQueryUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 flex items-center gap-1.5 rounded-lg border border-gray-800 px-3 py-2 text-[11px] text-blue-400 hover:border-gray-700 hover:bg-gray-800/40"
            >
              <ExternalLink className="h-3 w-3 shrink-0" />
              {hiddenCount > 0
                ? `View ${hiddenCount} more in Microsoft Graph Explorer`
                : "View full sign-in logs in Microsoft Graph Explorer"}
              <span className="text-gray-600">
                — search for &ldquo;{policyName}&rdquo; in the results
              </span>
            </a>
          )}
        </div>
      )}
    </div>
  );
}

function SignInMatchRow({ match, fallbackLogQueryUrl }: { match: PolicySignInMatch; fallbackLogQueryUrl: string }) {
  // Prefers a link scoped to this exact user + a narrow (+/-2h) time window -
  // both userPrincipalName and createdDateTime are documented as filterable
  // on /auditLogs/signIns, unlike policy attribution. Falls back to the
  // date-only, policy-wide link for matches with no userPrincipalName (e.g.
  // workload identity sign-ins), where the narrow filter can't be built.
  const matchUrl = buildSignInMatchLogQueryUrl(match) ?? fallbackLogQueryUrl;

  return (
    <tr className="border-b border-gray-800 last:border-0">
      <td className="px-3 py-1.5 text-gray-300">{match.userPrincipalName ?? "—"}</td>
      <td className="px-3 py-1.5 font-mono text-gray-400 whitespace-nowrap">
        {new Date(match.createdDateTime).toISOString().replace("T", " ").slice(0, 16)} UTC
      </td>
      <td className="px-3 py-1.5 text-gray-400">{match.location ?? "—"}</td>
      <td className="px-3 py-1.5 text-gray-400">{match.clientAppUsed ?? "—"}</td>
      <td className="px-3 py-1.5">
        <span
          className={cn(
            "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
            match.status === "blocked"
              ? "bg-red-500/10 text-red-400"
              : "bg-amber-500/10 text-amber-400"
          )}
        >
          {match.status === "blocked" ? "Blocked" : "Would block"}
        </span>
      </td>
      <td className="px-3 py-1.5 text-gray-400">
        {match.failureReason ?? "—"}
        {match.failureDetail && (
          <div className="mt-0.5 text-[10px] text-gray-600">{match.failureDetail}</div>
        )}
      </td>
      <td className="px-3 py-1.5">
        <a
          href={matchUrl}
          target="_blank"
          rel="noopener noreferrer"
          title="View this sign-in in Microsoft Graph Explorer"
          className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
        >
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </td>
    </tr>
  );
}

function PolicyCard({ result, resolverMaps, policySignInMatches }: { result: PolicyResult; resolverMaps?: GuidResolverMaps; policySignInMatches?: PolicySignInLogResult }) {
  const [expanded, setExpanded] = useState(false);
  const { policy, visualization, findings } = result;

  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");

  return (
    <div
      className={cn(
        "rounded-xl border transition-colors",
        hasCritical
          ? "border-red-500/30 bg-red-500/5"
          : hasHigh
          ? "border-orange-500/20 bg-orange-500/5"
          : "border-gray-800 bg-gray-900"
      )}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-3 p-4 text-left"
      >
        <div>
          {expanded ? (
            <ChevronDown className="h-5 w-5 text-gray-500" />
          ) : (
            <ChevronRight className="h-5 w-5 text-gray-500" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "text-xs font-medium rounded px-1.5 py-0.5",
                policy.state === "enabled"
                  ? "bg-green-500/10 text-green-400"
                  : policy.state === "enabledForReportingButNotEnforced"
                  ? "bg-yellow-500/10 text-yellow-400"
                  : "bg-gray-800 text-gray-500"
              )}
            >
              {visualization.state}
            </span>
            <h3 className="text-sm font-semibold text-white truncate">
              {policy.displayName}
            </h3>
          </div>
          <div className="mt-1 flex flex-wrap gap-3 text-xs text-gray-500">
            <span>{visualization.targetUsers}</span>
            <span>→</span>
            <span>{visualization.targetApps}</span>
            <span>→</span>
            <span>
              {visualization.grantControls.length > 0
                ? visualization.grantControls.join(", ")
                : "No grant controls"}
            </span>
          </div>
        </div>
        {findings.length > 0 && (
          <div className="flex items-center gap-1.5 shrink-0">
            <AlertCircle
              className={cn(
                "h-4 w-4",
                hasCritical
                  ? "text-red-400"
                  : hasHigh
                  ? "text-orange-400"
                  : "text-yellow-400"
              )}
            />
            <span className="text-xs text-gray-400">
              {findings.length} finding{findings.length !== 1 ? "s" : ""}
            </span>
          </div>
        )}
      </button>

      {/* Expanded Detail */}
      {expanded && (
        <div className="border-t border-gray-800 p-4">
          {/* Flow Visualization */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <PolicyFlowSection
              icon={Users}
              label="Users"
              items={[visualization.targetUsers]}
            />
            <PolicyFlowSection
              icon={Cloud}
              label="Cloud Apps"
              items={[visualization.targetApps]}
            />
            <PolicyFlowSection
              icon={Filter}
              label="Conditions"
              items={visualization.conditions}
              emptyText="No conditions"
            />
            <PolicyFlowSection
              icon={ShieldCheck}
              label="Grant Controls"
              items={visualization.grantControls}
              emptyText="No grant controls"
            />
            <PolicyFlowSection
              icon={Clock}
              label="Session Controls"
              items={visualization.sessionControls}
              emptyText="No session controls"
            />
          </div>

          {/* Condition Details - roles resolved to friendly names */}
          {(() => {
            const u = policy.conditions.users;
            const rows: [string, string][] = [];
            if (u.includeUsers.length > 0 && !u.includeUsers.includes("All") && !u.includeUsers.includes("None") && !u.includeUsers.includes("GuestsOrExternalUsers"))
              rows.push(["Include Users", resolveGuidList(u.includeUsers, resolverMaps)]);
            if (u.excludeUsers.length > 0)
              rows.push(["Exclude Users", resolveGuidList(u.excludeUsers, resolverMaps)]);
            if (u.includeGroups.length > 0)
              rows.push(["Include Groups", resolveGuidList(u.includeGroups, resolverMaps)]);
            if (u.excludeGroups.length > 0)
              rows.push(["Exclude Groups", resolveGuidList(u.excludeGroups, resolverMaps)]);
            if (u.includeRoles.length > 0)
              rows.push(["Include Roles", resolveRoleList(u.includeRoles, resolverMaps)]);
            if (u.excludeRoles.length > 0)
              rows.push(["Exclude Roles", resolveRoleList(u.excludeRoles, resolverMaps)]);
            const includeGuests = describeGuestsOrExternalUsers(u.includeGuestsOrExternalUsers);
            if (includeGuests) rows.push(["Include Guests", includeGuests]);
            const excludeGuests = describeGuestsOrExternalUsers(u.excludeGuestsOrExternalUsers);
            if (excludeGuests) rows.push(["Exclude Guests", excludeGuests]);
            if (policy.conditions.clientAppTypes.length > 0)
              rows.push(["Client App Types", policy.conditions.clientAppTypes.join(", ")]);
            if (policy.conditions.platforms?.includePlatforms.length)
              rows.push(["Platforms", policy.conditions.platforms.includePlatforms.join(", ")]);
            if (policy.conditions.userRiskLevels.length > 0)
              rows.push(["User Risk", policy.conditions.userRiskLevels.join(", ")]);
            if (policy.conditions.signInRiskLevels.length > 0)
              rows.push(["Sign-in Risk", policy.conditions.signInRiskLevels.join(", ")]);

            if (rows.length === 0) return null;
            return (
              <div className="mt-4">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                  Condition Details
                </h4>
                <div className="rounded-lg border border-gray-800 overflow-hidden">
                  <table className="w-full text-xs">
                    <tbody>
                      {rows.map(([label, value]) => (
                        <tr key={label} className="border-b border-gray-800 last:border-0">
                          <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                            {label}
                          </td>
                          <td className="px-3 py-1.5 text-gray-300 break-all">
                            {value}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })()}

{/* Policy Findings - grouped by severity with dropdowns */}
            {findings.length > 0 && (
              <div className="mt-4 space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Findings for this policy
                </h4>
                <FindingsGrouped findings={findings} />
            </div>
          )}

          {/* Sign-in log matches - blocked / would-block sign-ins attributed to this policy */}
          <PolicySignInMatchesSection policyId={policy.id} policyName={policy.displayName} result={policySignInMatches} />

          {/* Raw Policy ID */}
          <p className="mt-3 text-xs text-gray-700 font-mono">
            ID: {policy.id}
          </p>
        </div>
      )}
    </div>
  );
}

/** Detect Microsoft-managed / built-in policies */
function isMicrosoftManaged(result: PolicyResult): boolean {
  const p = result.policy;
  // Graph sets templateId on Microsoft-managed policies
  if (p.templateId && p.templateId !== "00000000-0000-0000-0000-000000000000") return true;
  // Fallback: naming convention
  const name = p.displayName.toLowerCase();
  return name.startsWith("microsoft-managed") || name.startsWith("[microsoft");
}

export function PolicyList({
  results,
  hideMicrosoft,
  onToggleHideMicrosoft,
  resolverMaps,
  policySignInMatches,
}: {
  results: PolicyResult[];
  hideMicrosoft: boolean;
  onToggleHideMicrosoft: (val: boolean) => void;
  resolverMaps?: GuidResolverMaps;
  policySignInMatches?: PolicySignInLogResult;
}) {
  const [sortBy, setSortBy] = useState<"findings" | "name" | "state">("findings");
  const [search, setSearch] = useState("");

  const microsoftCount = results.filter(isMicrosoftManaged).length;

  const filtered = results.filter((r) => {
    if (hideMicrosoft && isMicrosoftManaged(r)) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const p = r.policy;
      const v = r.visualization;
      return (
        p.displayName.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q) ||
        v.targetUsers.toLowerCase().includes(q) ||
        v.targetApps.toLowerCase().includes(q) ||
        v.grantControls.some((c) => c.toLowerCase().includes(q)) ||
        v.conditions.some((c) => c.toLowerCase().includes(q)) ||
        p.state.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const sorted = [...filtered].sort((a, b) => {
    switch (sortBy) {
      case "findings":
        return b.findings.length - a.findings.length;
      case "name":
        return a.policy.displayName.localeCompare(b.policy.displayName);
      case "state":
        return a.policy.state.localeCompare(b.policy.state);
      default:
        return 0;
    }
  });

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h3 className="text-lg font-semibold text-white">
          Policies{" "}
          <span className="text-gray-500 font-normal">
            ({filtered.length}{hideMicrosoft || search ? ` of ${results.length}` : ""})
          </span>
        </h3>
        <div className="flex flex-wrap items-center gap-2">
          {/* Hide Microsoft-managed toggle */}
          {microsoftCount > 0 && (
            <button
              onClick={() => onToggleHideMicrosoft(!hideMicrosoft)}
              className={cn(
                "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                hideMicrosoft
                  ? "bg-purple-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:text-white"
              )}
            >
              {hideMicrosoft ? `Show Microsoft (${microsoftCount})` : "Hide Microsoft"}
            </button>
          )}

          {/* Sort buttons */}
          <div className="flex gap-1">
            {(["findings", "name", "state"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSortBy(s)}
                className={cn(
                  "rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                  sortBy === s
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                )}
              >
                {s === "findings" ? "Most Findings" : s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search policies by name, state, users, apps, controls…"
          className="w-full rounded-lg border border-gray-700 bg-gray-800/50 py-2 pl-9 pr-9 text-sm text-gray-200 placeholder:text-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors"
        />
        {search && (
          <button
            onClick={() => setSearch("")}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      <div className="space-y-2">
        {sorted.map((result) => (
          <PolicyCard key={result.policy.id} result={result} resolverMaps={resolverMaps} policySignInMatches={policySignInMatches} />
        ))}
        {sorted.length === 0 && (
          <p className="py-8 text-center text-sm text-gray-500">
            No policies to display.
          </p>
        )}
      </div>
    </Card>
  );
}
