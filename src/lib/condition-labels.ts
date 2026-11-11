/**
 * Display labels for Conditional Access conditions and controls that the
 * policy and policy-plan summaries need to show but that don't fit the simple
 * "list of GUIDs" shape: guest/external user targeting, authentication flows,
 * and terms of use. Shared by `buildVisualization` (analyzer.ts) and
 * `summarizeConditionSet` / `summarizeControls` (policy-plan-visualizer.ts) so
 * the Policies and Policy Plans tabs describe the same configuration the same
 * way. Display only - the analysis reads these fields directly.
 */

/** Graph `conditionalAccessGuestOrExternalUserTypes` flag → label (matches analyzer.ts wording). */
const GUEST_TYPE_LABELS: Record<string, string> = {
  internalGuest: "Internal guests",
  b2bCollaborationGuest: "B2B Collaboration guests",
  b2bCollaborationMember: "B2B Collaboration members",
  b2bDirectConnectUser: "B2B Direct Connect users",
  otherExternalUser: "Other external users",
  serviceProvider: "Service provider users",
};

const ALL_GUEST_TYPE_COUNT = Object.keys(GUEST_TYPE_LABELS).length;

interface ParsedGuestsOrExternalUsers {
  types: string[];
  /** "all" for every external tenant, otherwise the number of enumerated tenants (null if unstated). */
  tenants: "all" | number | null;
}

/**
 * Parses `includeGuestsOrExternalUsers` / `excludeGuestsOrExternalUsers`.
 * Returns null when the value is absent or carries no guest types - Graph
 * returns `null` for an unset condition, and an empty object is not targeting.
 */
function parseGuestsOrExternalUsers(value: unknown): ParsedGuestsOrExternalUsers | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const raw = record.guestOrExternalUserTypes;
  const types =
    typeof raw === "string"
      ? raw.split(",").map((t) => t.trim()).filter((t) => t && t !== "none")
      : [];
  if (types.length === 0) return null;

  let tenants: ParsedGuestsOrExternalUsers["tenants"] = null;
  const ext = record.externalTenants;
  if (ext && typeof ext === "object") {
    const e = ext as Record<string, unknown>;
    if (e.membershipKind === "all") tenants = "all";
    else if (Array.isArray(e.members)) tenants = e.members.length;
  }
  return { types, tenants };
}

/** Short form for a one-line summary, e.g. "Guests / external users (6 types)". */
export function summarizeGuestsOrExternalUsers(value: unknown): string | null {
  const parsed = parseGuestsOrExternalUsers(value);
  if (!parsed) return null;
  if (parsed.types.length === 1) {
    return GUEST_TYPE_LABELS[parsed.types[0]] ?? parsed.types[0];
  }
  return parsed.types.length >= ALL_GUEST_TYPE_COUNT
    ? "All guest / external user types"
    : `Guests / external users (${parsed.types.length} types)`;
}

/** Full form for a details table: every type, plus which external tenants. */
export function describeGuestsOrExternalUsers(value: unknown): string | null {
  const parsed = parseGuestsOrExternalUsers(value);
  if (!parsed) return null;
  const types = parsed.types.map((t) => GUEST_TYPE_LABELS[t] ?? t).join(", ");
  if (parsed.tenants === "all") return `${types} (all external tenants)`;
  if (typeof parsed.tenants === "number") {
    return `${types} (${parsed.tenants} specific external tenant${parsed.tenants === 1 ? "" : "s"})`;
  }
  return types;
}

const TRANSFER_METHOD_LABELS: Record<string, string> = {
  deviceCodeFlow: "Device code flow",
  authenticationTransfer: "Authentication transfer",
};

/**
 * `authenticationFlows.transferMethods` as a condition line. Without it a
 * "block device code flow" policy reads as "All users → All cloud apps →
 * Block access", which looks like a tenant-wide block.
 */
export function describeAuthenticationFlows(
  flows: { transferMethods?: string } | null | undefined
): string | null {
  const methods = (flows?.transferMethods ?? "")
    .split(",")
    .map((m) => m.trim())
    .filter((m) => m && m !== "none");
  if (methods.length === 0) return null;
  return `Authentication flows: ${methods.map((m) => TRANSFER_METHOD_LABELS[m] ?? m).join(", ")}`;
}

/** Terms of use as a grant control - a grant in its own right, not "no grant controls". */
export function describeTermsOfUse(ids: string[] | null | undefined): string | null {
  const count = ids?.length ?? 0;
  if (count === 0) return null;
  return count === 1 ? "📄 Accept terms of use" : `📄 Accept terms of use (${count})`;
}
