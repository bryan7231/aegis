import { Link } from "@tanstack/react-router";
import { motion } from "motion/react";
import {
  ShieldCheck,
  GitBranch,
  Network,
  Target,
  ListChecks,
  Workflow,
  ArrowRight,
  Zap,
  Lock,
  Sparkles,
} from "lucide-react";
import heroGraph from "@/assets/hero-graph.png";
import logoWhite from "@/assets/logo_white.png";

export function LandingPage() {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-background text-foreground">
      <Nav />
      <Hero />
      <Logos />
      <Features />
      <HowItWorks />
      <Showcase />
      <CTA />
      <Footer />
    </div>
  );
}

/* -------------------------------- NAV -------------------------------- */

function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-border/60 bg-background/70 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <a href="#top" className="flex items-center gap-2">
          <Logo className="h-7 w-auto" />
          <span className="ml-2 hidden rounded-full border border-border bg-secondary px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground sm:inline">
            v0.1 · beta
          </span>
        </a>
        <nav className="hidden items-center gap-8 text-sm text-muted-foreground md:flex">
          <a href="#features" className="transition-colors hover:text-foreground">Features</a>
          <a href="#how" className="transition-colors hover:text-foreground">How it works</a>
          <a href="#showcase" className="transition-colors hover:text-foreground">Demo</a>
        </nav>
        <Link
          to="/sign-in"
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground transition-all hover:bg-primary/90 hover:shadow-glow"
        >
          Sign in
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </header>
  );
}

function Logo({ className = "" }: { className?: string }) {
  return (
    <img
      src={logoWhite}
      alt="Aegis logo"
      className={`object-contain ${className}`}
    />
  );
}

/* -------------------------------- HERO -------------------------------- */

function Hero() {
  return (
    <section id="top" className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0 bg-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-[600px] bg-[radial-gradient(ellipse_60%_50%_at_50%_0%,rgba(59,130,246,0.18),transparent_70%)]" />

      <div className="relative mx-auto max-w-7xl px-6 pt-20 pb-24 sm:pt-28 sm:pb-32">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="mx-auto max-w-3xl text-center"
        >
          <h1 className="mt-6 text-balance text-5xl font-semibold leading-[1.05] tracking-tight sm:text-6xl md:text-7xl">
            <span className="text-gradient">Break the attack chain</span>
            <br />
            <span className="text-gradient-primary">before it breaks you.</span>
          </h1>

          <p className="mx-auto mt-6 max-w-2xl text-pretty text-base leading-relaxed text-muted-foreground sm:text-lg">
            Aegis scans your repo, chains individually low-severity CVEs into the real
            attack paths an adversary would walk, and tells you the{" "}
            <span className="text-foreground">smallest fix that collapses the most attacks.</span>
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              to="/sign-in"
              className="group inline-flex items-center gap-2 rounded-md bg-primary px-5 py-3 text-sm font-semibold text-primary-foreground shadow-glow transition-all hover:bg-primary/90"
            >
              Sign in
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <a
              href="#how"
              className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-5 py-3 text-sm font-medium text-foreground transition-colors hover:bg-secondary"
            >
              See how it works
            </a>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 28 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="relative mx-auto mt-16 max-w-5xl"
        >
          <div className="absolute -inset-x-10 -inset-y-8 -z-10 bg-[radial-gradient(ellipse_at_center,rgba(59,130,246,0.25),transparent_60%)] blur-2xl" />
          <div className="relative overflow-hidden rounded-2xl border border-border surface-card">
            <div className="flex items-center gap-2 border-b border-border bg-card/80 px-4 py-3">
              <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
              <span className="ml-3 font-mono text-xs text-muted-foreground">
                aegis · attack-graph · main
              </span>
            </div>
            <div className="relative">
              <img
                src={heroGraph}
                alt="Aegis attack-path graph visualization with glowing nodes and edges"
                width={1600}
                height={1200}
                className="w-full opacity-90"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-card via-transparent to-transparent" />
              <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent animate-scan" />

              <FloatingChip className="left-[8%] top-[18%]" tone="primary">
                <Network className="h-3 w-3" /> 1,284 packages
              </FloatingChip>
              <FloatingChip className="right-[10%] top-[28%]" tone="destructive">
                <Zap className="h-3 w-3" /> 9 attack paths
              </FloatingChip>
              <FloatingChip className="bottom-[14%] left-[12%]" tone="success">
                <ListChecks className="h-3 w-3" /> Fix 2 → collapse 8
              </FloatingChip>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

function FloatingChip({
  children,
  className = "",
  tone = "primary",
}: {
  children: React.ReactNode;
  className?: string;
  tone?: "primary" | "destructive" | "success";
}) {
  const toneClasses = {
    primary: "border-primary/40 bg-primary/10 text-primary-glow",
    destructive: "border-destructive/40 bg-destructive/10 text-destructive",
    success: "border-success/40 bg-success/10 text-success",
  }[tone];

  return (
    <div
      className={`absolute hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium backdrop-blur-md md:inline-flex ${toneClasses} ${className}`}
    >
      {children}
    </div>
  );
}

/* -------------------------------- LOGOS -------------------------------- */

function Logos() {
  const items = ["GitHub", "OSV.dev", "npm", "PyPI", "GHSA", "Snyk DB"];
  return (
    <section className="border-y border-border/60 bg-card/30">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <p className="text-center text-xs uppercase tracking-[0.2em] text-muted-foreground">
          Powered by trusted vulnerability sources
        </p>
        <div className="mt-5 flex flex-wrap items-center justify-center gap-x-12 gap-y-4">
          {items.map((i) => (
            <span key={i} className="font-mono text-base font-semibold tracking-tight text-muted-foreground/80">
              {i}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------- FEATURES ------------------------------- */

const features = [
  {
    icon: Network,
    title: "Interactive attack graph",
    desc: "A 3D graph of your dependencies and the exploit chains between them — not a flat CSV.",
  },
  {
    icon: GitBranch,
    title: "Chain low-severity CVEs",
    desc: "Aegis links 'medium' flaws into the realistic attack paths an adversary actually walks.",
  },
  {
    icon: Target,
    title: "Find the bridge nodes",
    desc: "Surface the few packages every attack path routes through, ranked by blast radius.",
  },
  {
    icon: ListChecks,
    title: "Minimal remediation plan",
    desc: "Get an ordered fix list: 'upgrade these two and 8 of 9 paths collapse.'",
  },
  {
    icon: Workflow,
    title: "Triage that fits your day",
    desc: "Priority queue with explanations, drop-in patches, and copy-pasteable upgrade commands.",
  },
  {
    icon: Lock,
    title: "Deterministic & verifiable",
    desc: "Built on osv-scanner data — every finding is reproducible, every link is auditable.",
  },
];

function Features() {
  return (
    <section id="features" className="relative">
      <div className="mx-auto max-w-7xl px-6 py-24 sm:py-32">
        <SectionHeading
          eyebrow="Features"
          title="Not 'what's wrong.' What to fix first."
          subtitle="Most scanners hand you 400 rows and walk away. Aegis hands you a plan."
        />

        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-80px" }}
              transition={{ duration: 0.4, delay: i * 0.05 }}
              className="group relative overflow-hidden rounded-xl border border-border surface-card p-6 transition-all hover:border-primary/40"
            >
              <div className="pointer-events-none absolute -right-12 -top-12 h-32 w-32 rounded-full bg-primary/10 opacity-0 blur-2xl transition-opacity group-hover:opacity-100" />
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-secondary text-primary">
                <f.icon className="h-5 w-5" />
              </div>
              <h3 className="mt-5 text-base font-semibold tracking-tight">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{f.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

function SectionHeading({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="text-xs font-medium uppercase tracking-[0.2em] text-primary">{eyebrow}</p>
      <h2 className="mt-3 text-balance text-3xl font-semibold tracking-tight text-gradient sm:text-4xl">
        {title}
      </h2>
      {subtitle && (
        <p className="mt-4 text-pretty text-base text-muted-foreground">{subtitle}</p>
      )}
    </div>
  );
}

/* ------------------------------ HOW IT WORKS ------------------------------ */

const steps = [
  {
    n: "01",
    title: "Connect your repo",
    desc: "Paste your repository URL or select from GitHub. Aegis clones, resolves, and maps your full dependency tree.",
    code: "github.com/acme/web-app",
  },
  {
    n: "02",
    title: "Scan for vulnerabilities",
    desc: "Every installed version is checked against OSV, GHSA, and the public CVE corpus — deterministically.",
    code: "→ 1,284 packages · 47 CVEs found",
  },
  {
    n: "03",
    title: "Visualize attack paths",
    desc: "Nodes are packages, edges are chained exploits. Bridge nodes glow — they're where attacks converge.",
    code: "→ 9 attack paths · 3 bridge nodes",
  },
  {
    n: "04",
    title: "Generate the minimal fix",
    desc: "Aegis returns an ordered plan with exact upgrade commands. Fix the two that matter, skip the noise.",
    code: "✓ upgrade lodash@4.17.21 → 8 paths closed",
  },
];

function HowItWorks() {
  return (
    <section id="how" className="relative border-t border-border/60 bg-card/20">
      <div className="mx-auto max-w-7xl px-6 py-24 sm:py-32">
        <SectionHeading
          eyebrow="How it works"
          title="From repo URL to a fix plan in under a minute."
        />

        <div className="mt-16 grid gap-4 lg:grid-cols-2">
          {steps.map((s, i) => (
            <motion.div
              key={s.n}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-80px" }}
              transition={{ duration: 0.4, delay: i * 0.06 }}
              className="relative overflow-hidden rounded-xl border border-border surface-card p-7"
            >
              <div className="flex items-start gap-5">
                <div className="font-mono text-3xl font-light text-primary/60">{s.n}</div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold tracking-tight">{s.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{s.desc}</p>
                  <div className="mt-5 rounded-md border border-border bg-background/60 px-3 py-2 font-mono text-xs text-muted-foreground">
                    <span className="text-success">{s.code}</span>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* -------------------------------- SHOWCASE -------------------------------- */

function Showcase() {
  return (
    <section id="showcase" className="relative">
      <div className="mx-auto max-w-7xl px-6 py-24 sm:py-32">
        <div className="grid items-center gap-12 lg:grid-cols-2">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
          >
            <p className="text-xs font-medium uppercase tracking-[0.2em] text-primary">
              The triage view
            </p>
            <h2 className="mt-3 text-balance text-3xl font-semibold tracking-tight text-gradient sm:text-4xl">
              Severity isn't priority. Aegis ranks by blast radius.
            </h2>
            <p className="mt-5 text-pretty text-base leading-relaxed text-muted-foreground">
              CVSS tells you how scary one flaw is in isolation. Aegis tells you which
              flaws actually get reached, how many attack paths they unlock, and what
              an attacker can do once they're through.
            </p>
            <ul className="mt-8 space-y-3 text-sm">
              {[
                "Ordered queue — fix the first, see the graph collapse",
                "Per-CVE explainer: how it's reached and what it unlocks",
                "Drop-in upgrade commands for npm, pip, and cargo",
                "Export as a PR-ready Markdown remediation plan",
              ].map((t) => (
                <li key={t} className="flex items-start gap-3 text-muted-foreground">
                  <ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-primary" />
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="relative"
          >
            <div className="absolute -inset-4 -z-10 bg-[radial-gradient(ellipse_at_center,rgba(59,130,246,0.2),transparent_70%)] blur-2xl" />
            <TriageCard />
          </motion.div>
        </div>
      </div>
    </section>
  );
}

function TriageCard() {
  const rows = [
    { id: "CVE-2024-21538", pkg: "cross-spawn", sev: "high", paths: 6, fix: "7.0.5" },
    { id: "CVE-2024-4068", pkg: "braces", sev: "medium", paths: 4, fix: "3.0.3" },
    { id: "CVE-2024-37890", pkg: "ws", sev: "high", paths: 3, fix: "8.17.1" },
    { id: "CVE-2024-29415", pkg: "ip", sev: "medium", paths: 2, fix: "2.0.1" },
    { id: "CVE-2024-28849", pkg: "follow-redirects", sev: "medium", paths: 1, fix: "1.15.6" },
  ];
  return (
    <div className="overflow-hidden rounded-2xl border border-border surface-card">
      <div className="flex items-center justify-between border-b border-border bg-card/80 px-5 py-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold">Remediation Queue</span>
        </div>
        <span className="font-mono text-[11px] text-muted-foreground">
          16 collapsed / 18 paths
        </span>
      </div>
      <div className="divide-y divide-border">
        {rows.map((r, idx) => (
          <div key={r.id} className="flex items-center gap-4 px-5 py-3.5">
            <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md bg-secondary font-mono text-xs text-muted-foreground">
              {idx + 1}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-sm font-medium">{r.pkg}</span>
                <span
                  className={`rounded-sm px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                    r.sev === "high"
                      ? "bg-destructive/15 text-destructive"
                      : "bg-warning/15 text-warning"
                  }`}
                >
                  {r.sev}
                </span>
              </div>
              <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                {r.id} · breaks {r.paths} paths
              </div>
            </div>
            <div className="hidden font-mono text-xs text-success sm:block">→ {r.fix}</div>
          </div>
        ))}
      </div>
      <div className="border-t border-border bg-background/40 px-5 py-3 text-center font-mono text-[11px] text-muted-foreground">
        <Sparkles className="mr-1 inline h-3 w-3 text-primary" />
        Fix the top 2 and your repo's attack surface shrinks by 78%.
      </div>
    </div>
  );
}

/* ---------------------------------- CTA ---------------------------------- */

function CTA() {
  return (
    <section className="relative">
      <div className="mx-auto max-w-5xl px-6 py-24 sm:py-32">
        <div className="relative overflow-hidden rounded-3xl border border-border surface-card px-8 py-16 text-center sm:px-16">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(59,130,246,0.25),transparent_70%)]" />
          <div className="pointer-events-none absolute inset-0 bg-grid opacity-50" />

          <div className="relative">
            <div className="mx-auto inline-flex h-20 w-20 items-center justify-center rounded-2xl bg-primary/10 shadow-glow">
              <Logo className="h-12 w-auto" />
            </div>
            <h2 className="mt-6 text-balance text-3xl font-semibold tracking-tight sm:text-4xl">
              Stop firefighting CVEs. <span className="text-gradient-primary">Start breaking chains.</span>
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-pretty text-muted-foreground">
              Sign up, connect your repo, and see your attack graph in under a minute.
              No setup, no CLI, no noise.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <Link
                to="/sign-in"
                className="group inline-flex items-center gap-2 rounded-md bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground shadow-glow transition-all hover:bg-primary/90"
              >
                Sign in
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
              </Link>
              <a
                href="#how"
                className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-6 py-3 text-sm font-medium transition-colors hover:bg-secondary"
              >
                See how it works
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* -------------------------------- FOOTER -------------------------------- */

function Footer() {
  return (
    <footer className="border-t border-border/60">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 py-10 sm:flex-row">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Logo className="h-5 w-auto" />
          <span>· The attack-path visualizer for real codebases.</span>
        </div>
        <div className="flex items-center gap-6 text-xs text-muted-foreground">
          <span>© 2026</span>
        </div>
      </div>
    </footer>
  );
}
