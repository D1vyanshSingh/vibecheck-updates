export const primaryNav = [
  { label: "Platform", href: "/platform" },
  { label: "How It Works", href: "/how-it-works" },
  { label: "Integrations", href: "/integrations" },
  { label: "Developers", href: "/developers" },
  { label: "Scanner", href: "/scan" },
  { label: "Pricing", href: "/pricing" },
] as const;

export const secondaryNav = [
  { label: "About", href: "/about" },
] as const;

export type CapabilityStatus = "mvp" | "development" | "planned";

export type Capability = {
  id: string;
  index: string;
  title: string;
  summary: string;
  detail: string;
  signals: string[];
  status: CapabilityStatus;
};

export const capabilities: Capability[] = [
  {
    id: "code-security",
    index: "01",
    title: "Code security",
    summary: "Review what the model wrote, not only what you remember writing.",
    detail:
      "VibeCheck inspects application source for patterns that lead to real exposure: unsanitised input paths, unsafe query construction, broken authorisation checks and risky use of framework primitives. Findings are linked to the exact file and line, with the reasoning written out.",
    signals: ["Injection paths", "Broken access checks", "Unsafe deserialisation"],
    status: "mvp",
  },
  {
    id: "secrets",
    index: "02",
    title: "Secret exposure",
    summary: "Find keys that shipped before they cost you a weekend.",
    detail:
      "Services keys, database URLs and tokens leak through generated config, copied examples and client bundles. VibeCheck scans tracked files and build output for credential shapes, then reports the location and a safe rotation path.",
    signals: ["Hard-coded credentials", "Client bundle leakage", "Stale environment keys"],
    status: "mvp",
  },
  {
    id: "dependencies",
    index: "03",
    title: "Dependency risk",
    summary: "Understand what your package tree actually pulls in.",
    detail:
      "Generated projects add dependencies quickly. VibeCheck maps direct and transitive packages against known advisories and flags abandoned or unpinned ranges, with a clear note on whether the vulnerable path is reachable from your code.",
    signals: ["Known advisories", "Unpinned ranges", "Reachability context"],
    status: "development",
  },
  {
    id: "data-access",
    index: "04",
    title: "Database & access control",
    summary: "Check that a signed-in user can only reach their own rows.",
    detail:
      "A generated backend often forgets the ownership clause. VibeCheck reviews schema definitions, query filters and row-level policies to identify tables that are readable or writable without a tenant boundary, and explains the missing condition.",
    signals: ["Row-level policy gaps", "Missing tenant filters", "Over-broad roles"],
    status: "development",
  },
  {
    id: "configuration",
    index: "05",
    title: "Application configuration",
    summary: "Defaults are convenient until they are production.",
    detail:
      "Permissive CORS, debug modes, public storage buckets, missing security headers and weak session settings are checked against the environment you are deploying to, so development defaults do not silently ship.",
    signals: ["CORS policy", "Security headers", "Storage permissions"],
    status: "planned",
  },
  {
    id: "explanations",
    index: "06",
    title: "AI-assisted explanations",
    summary: "A finding you do not understand is a finding you will ignore.",
    detail:
      "Each issue is explained in plain language: what an attacker could do with it, what precondition the exploit needs, and how confident the analysis is. Model output is treated as a draft explanation, never as proof, and the underlying evidence stays visible.",
    signals: ["Attack narrative", "Preconditions", "Confidence, not certainty"],
    status: "development",
  },
  {
    id: "remediation",
    index: "07",
    title: "Remediation guidance",
    summary: "Fix directions that respect how the application is written.",
    detail:
      "Suggested fixes are written against your framework and your conventions, with a diff-style patch and the reasoning behind it. You review and apply the change; nothing is committed or deployed on your behalf.",
    signals: ["Patch previews", "Framework-aware advice", "Human approval"],
    status: "development",
  },
  {
    id: "verification",
    index: "08",
    title: "Security verification",
    summary: "Re-run the check and prove the weakness is gone.",
    detail:
      "Verification records the finding, the fix and the re-test result as one traceable record, so a resolved issue can be demonstrated rather than assumed. Continuous monitoring on every change is on the roadmap.",
    signals: ["Re-test on demand", "Finding history", "Regression watch (planned)"],
    status: "planned",
  },
];

export type WorkflowStep = {
  index: string;
  title: string;
  summary: string;
  detail: string;
  automation: "automated" | "assisted" | "manual";
  automationNote: string;
};

export const workflowSteps: WorkflowStep[] = [
  {
    index: "01",
    title: "Connect your project",
    summary: "Point VibeCheck at a repository you already own.",
    detail:
      "Read-only access to the repository is enough to start. Credentials are held server-side, scoped to the installation, and can be revoked at any time.",
    automation: "automated",
    automationNote: "Repository authorisation is a one-time setup step.",
  },
  {
    index: "02",
    title: "Analyse the application",
    summary: "Map the code, data model, auth flow and deployment surface.",
    detail:
      "Static analysis builds a model of routes, data access and configuration. Analysis runs out of band and never executes application code.",
    automation: "automated",
    automationNote: "Static analysis only in the current design.",
  },
  {
    index: "03",
    title: "Discover security weaknesses",
    summary: "Surface findings with location and supporting evidence.",
    detail:
      "Each finding carries the file, the line, the rule that matched and the surrounding context, so it can be checked by a human rather than taken on faith.",
    automation: "automated",
    automationNote: "Rule-based detection; coverage is not exhaustive.",
  },
  {
    index: "04",
    title: "Understand the risk",
    summary: "Read what an attacker gains and what must be true first.",
    detail:
      "Explanations are drafted with a model and grounded in the matched evidence. Confidence and preconditions are shown alongside the narrative.",
    automation: "assisted",
    automationNote: "Model-written explanations require review.",
  },
  {
    index: "05",
    title: "Review recommended fixes",
    summary: "Accept, edit or reject a patch — the decision stays yours.",
    detail:
      "Suggested changes are presented as diffs against your current branch. VibeCheck does not commit, merge or deploy anything.",
    automation: "manual",
    automationNote: "Application of fixes is manual by design.",
  },
  {
    index: "06",
    title: "Verify improvements",
    summary: "Re-test the original finding and record the result.",
    detail:
      "The issue is re-run against the updated code and closed only when the evidence supports it, leaving a verification record rather than a status dropdown.",
    automation: "automated",
    automationNote: "Continuous verification is planned, not live.",
  },
];

export type Integration = {
  name: string;
  glyph: string;
  category: string;
  status: CapabilityStatus;
  intent: string;
  note: string;
};

export const integrations: Integration[] = [
  {
    name: "GitHub",
    glyph: "GH",
    category: "Source control",
    status: "development",
    intent: "Connect a repository, analyse branches and report findings against pull requests.",
    note: "Private beta integration in active development. Not publicly available.",
  },
  {
    name: "GitLab",
    glyph: "GL",
    category: "Source control",
    status: "planned",
    intent: "Mirror the GitHub workflow for self-hosted and SaaS GitLab projects.",
    note: "Planned. No implementation has started.",
  },
  {
    name: "Vercel",
    glyph: "VC",
    category: "Deployment",
    status: "planned",
    intent: "Read deployment configuration and environment variable scope to catch shipping mistakes.",
    note: "Planned. Requires deployment-level read access design.",
  },
  {
    name: "Supabase",
    glyph: "SB",
    category: "Database & auth",
    status: "planned",
    intent: "Inspect row-level security policies and storage permissions against your schema.",
    note: "Planned. Policy analysis is in design.",
  },
  {
    name: "VS Code",
    glyph: "VS",
    category: "Editor",
    status: "planned",
    intent: "Show findings inline where the code is being written, with a link to the explanation.",
    note: "Planned. No extension is published.",
  },
  {
    name: "AI coding environments",
    glyph: "AI",
    category: "Generation",
    status: "planned",
    intent: "Explain security context to the assistant generating the code, before the change is accepted.",
    note: "Under research. No partnership or public integration exists.",
  },
];

export type Tier = {
  name: string;
  audience: string;
  price: string;
  priceNote: string;
  summary: string;
  includes: string[];
  cta: string;
  featured?: boolean;
  status: "waitlist" | "planned";
};

export const tiers: Tier[] = [
  {
    name: "Free / Community",
    audience: "Solo builders and vibe coders",
    price: "Coming soon",
    priceNote: "No price has been set.",
    summary:
      "A single project, core code and secret checks, and the full explanation for every finding.",
    includes: [
      "One connected project",
      "Core code and secret checks",
      "Finding explanations",
      "Community documentation access",
    ],
    cta: "Join the waitlist",
    status: "waitlist",
  },
  {
    name: "Pro",
    audience: "Indie hackers and AI application builders",
    price: "Coming soon",
    priceNote: "Pricing under review.",
    summary:
      "For builders shipping continuously: more projects, dependency and data-access analysis, verification history.",
    includes: [
      "Multiple projects",
      "Dependency and access-control analysis",
      "Remediation patch previews",
      "Verification history",
    ],
    cta: "Join the waitlist",
    status: "waitlist",
    featured: true,
  },
  {
    name: "Team / Agency",
    audience: "Agencies and small product teams",
    price: "Coming soon",
    priceNote: "Scoping with early design partners.",
    summary:
      "Shared workspaces, review ownership and a security record you can hand to a client.",
    includes: [
      "Shared workspaces",
      "Client-separated project scopes",
      "Finding assignment and ownership",
      "Exportable verification records",
    ],
    cta: "Talk to us",
    status: "planned",
  },
  {
    name: "Enterprise",
    audience: "SaaS engineering organisations",
    price: "Contact",
    priceNote: "No commercial terms published.",
    summary:
      "Private deployment options, custom policy coverage and integration support, defined case by case.",
    includes: [
      "Custom detection policy",
      "Deployment and network requirements review",
      "Integration support",
      "Security review documentation",
    ],
    cta: "Start a conversation",
    status: "planned",
  },
];

export const principles = [
  {
    index: "01",
    title: "Evidence over adjectives",
    body:
      "Every claim on this site and in the product has to point at something checkable: a line of code, a rule, a re-test result. If we cannot show the evidence, we do not say it.",
  },
  {
    index: "02",
    title: "Findings are hypotheses",
    body:
      "Analysis is not omniscience. Results carry confidence and preconditions, and reviewers are expected to disagree with us. A tool that is always right is a tool nobody checks.",
  },
  {
    index: "03",
    title: "The human keeps the pen",
    body:
      "We propose fixes and explain them. We do not commit, merge or deploy. Security tooling that can silently change production is a new attack surface, not a solution.",
  },
  {
    index: "04",
    title: "Least privilege, literally",
    body:
      "Read-only where read-only is enough. Scoped credentials, short-lived tokens and no copy of your source beyond what an analysis run needs.",
  },
  {
    index: "05",
    title: "Build for the generated decade",
    body:
      "The codebase of the next ten years will be mostly machine-authored. Security review has to keep up with that cadence without becoming a scrolling chore.",
  },
  {
    index: "06",
    title: "Say what is not done",
    body:
      "A roadmap is not a feature. Every capability on this site is labelled MVP, in development or planned, because confusing the three is how trust gets spent.",
  },
] as const;
