import type { ReactNode, ButtonHTMLAttributes, AnchorHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

/**
 * Primitives. Deliberately few: ONE primary button, ONE secondary, ONE surface.
 * Variants exist to express state, never to decorate — every extra variant is
 * a decision the system failed to make once.
 */

/* ── Identity ───────────────────────────────────────────────────────────── */

/** Reticle mark: a sight closing on a target. Square, 1px, acid. */
export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" aria-hidden className={cn("h-4 w-4", className)}>
      <rect x="0.5" y="0.5" width="15" height="15" fill="none" stroke="currentColor" />
      <rect x="6" y="6" width="4" height="4" fill="currentColor" />
      <path d="M8 0v3M8 13v3M0 8h3M13 8h3" stroke="currentColor" />
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-baseline gap-2.5", className)}>
      <Mark className="translate-y-[1px] text-acid" />
      <span className="font-display text-[1.05rem] font-bold tracking-tightest">auditer</span>
    </span>
  );
}

/* ── Type roles ─────────────────────────────────────────────────────────── */

/** Technical label. Every piece of metadata in the product wears this. */
export function Label({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("label", className)}>{children}</span>;
}

/** Section index + name, as on an instrument panel: `[03] PIPELINE`. */
export function SectionMark({ index, children }: { index: string; children: ReactNode }) {
  return (
    <div className="flex items-center gap-3 border-b border-line pb-3">
      <span className="font-mono text-label text-acid">[{index}]</span>
      <Label className="text-ash">{children}</Label>
    </div>
  );
}

/* ── Surfaces ───────────────────────────────────────────────────────────── */

export function Panel({
  children,
  className,
  ticked = false,
}: {
  children: ReactNode;
  className?: string;
  /** Corner ticks — reserve for the block that carries the most weight. */
  ticked?: boolean;
}) {
  return (
    <div className={cn("hairline bg-slate", ticked && "ticked", className)}>{children}</div>
  );
}

/* ── Actions ────────────────────────────────────────────────────────────── */

/** Wipe colour for the primary variant — set as a CSS var the pseudo reads. */
const BTN_BASE =
  "inline-flex items-center justify-center gap-2 whitespace-nowrap border px-5 py-2.5 " +
  "font-mono text-label uppercase transition-colors duration-[180ms] ease-out " +
  "disabled:pointer-events-none disabled:opacity-35";

const BTN_VARIANT = {
  // Filled acid — one per screen, on the single most important action. The
  // hover WIPES a darker fill in from the left rather than cross-fading the
  // background: a colour change says "state changed", a wipe says "the control
  // answered you". Same 320ms, entirely different read.
  primary:
    "btn-wipe border-acid bg-acid text-void [--wipe:theme(colors.acid-dim)] " +
    "hover:border-acid-dim",
  // Outline that inverts on hover. The default.
  ghost: "border-line-bright text-mineral hover:border-mineral hover:bg-mineral hover:text-void",
  // Text-weight action inside dense surfaces.
  quiet: "border-transparent px-2 text-ash hover:text-mineral",
  danger: "border-critical/50 text-critical hover:bg-critical hover:text-void",
} as const;

export type ButtonVariant = keyof typeof BTN_VARIANT;

const SIZES = { sm: "px-3 py-1.5", md: "", lg: "px-7 py-3.5 text-data" } as const;

export function Button({
  variant = "ghost",
  size = "md",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: keyof typeof SIZES }) {
  return <button className={cn(BTN_BASE, BTN_VARIANT[variant], SIZES[size], className)} {...props} />;
}

export function ButtonLink({
  variant = "ghost",
  size = "md",
  className,
  ...props
}: AnchorHTMLAttributes<HTMLAnchorElement> & { variant?: ButtonVariant; size?: keyof typeof SIZES }) {
  return <a className={cn(BTN_BASE, BTN_VARIANT[variant], SIZES[size], className)} {...props} />;
}

/* ── Data display ───────────────────────────────────────────────────────── */

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

const SEV_TEXT: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-info",
};
const SEV_BG: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
};

export function sevText(s: string): string {
  return SEV_TEXT[s] ?? "text-info";
}
export function sevBg(s: string): string {
  return SEV_BG[s] ?? "bg-info";
}

/** Square severity marker. Square, not a dot — dots read as decorative bullets. */
export function SevMark({ severity, className }: { severity: string; className?: string }) {
  return <span aria-hidden className={cn("h-2 w-2 shrink-0", sevBg(severity), className)} />;
}

export function Chip({
  children,
  className,
  tone = "neutral",
}: {
  children: ReactNode;
  className?: string;
  tone?: "neutral" | "acid" | "warn";
}) {
  const tones = {
    neutral: "border-line-bright text-ash",
    acid: "border-acid/40 text-acid",
    warn: "border-high/40 text-high",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 border px-2 py-0.5 font-mono text-label uppercase",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/** A single measured value: label above, value below in mono. */
export function Readout({
  label,
  value,
  hint,
  tone,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: string;
  className?: string;
}) {
  return (
    <div className={cn("border-l border-line pl-4", className)}>
      <Label>{label}</Label>
      <div className={cn("mt-2 font-display text-[2rem] font-bold leading-none tracking-tightest", tone)}>
        {value}
      </div>
      {hint && <div className="mt-1.5 font-mono text-label text-mute">{hint}</div>}
    </div>
  );
}

/* ── Forms ──────────────────────────────────────────────────────────────── */

/** Boxed 1px input, label above in mono. Never a placeholder-as-label. */
export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="label block text-ash">{label}</span>
      <div className="mt-2">{children}</div>
      {error ? (
        <span className="mt-1.5 block font-mono text-label text-critical">{error}</span>
      ) : hint ? (
        <span className="mt-1.5 block font-mono text-label text-mute">{hint}</span>
      ) : null}
    </label>
  );
}

export const inputClass =
  "w-full border border-line-bright bg-void px-3.5 py-3 font-mono text-data text-mineral " +
  "placeholder:text-mute/60 transition-colors duration-[180ms] focus:border-acid focus:outline-none";

/* ── States ─────────────────────────────────────────────────────────────── */

/** Empty state with the same craft as everything else: label, line, one action. */
export function Empty({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <div className="border border-dashed border-line px-6 py-14 text-center">
      <div className="mx-auto mb-4 h-px w-10 bg-line-bright" />
      <p className="font-display text-lede font-medium text-mineral">{title}</p>
      <p className="mx-auto mt-2 max-w-[46ch] text-data text-mute">{body}</p>
      {action && <div className="mt-6 flex justify-center">{action}</div>}
    </div>
  );
}

export function Spinner({ label = "loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2.5 font-mono text-label uppercase text-mute">
      <span className="h-1.5 w-1.5 animate-pulse-dot bg-acid" />
      {label}
    </div>
  );
}
