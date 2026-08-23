import type { Config } from "tailwindcss";

/**
 * Art direction: "technical instrument sheet" (tech-lab).
 *
 * Carbon ground, mineral ink, ONE brand accent (acid green). Severity colours
 * are deliberately NOT accents — they are a data scale, kept off the green hue
 * so the accent stays exclusive to the brand.
 *
 * Radius rule: surfaces are square (0). The only round things in the product
 * are avatars and the score dial, which are circles by nature. Anything
 * "medium rounded" is a decision not made.
 */
export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Ground → surface → line, four steps only.
        void: "#07090A",
        carbon: "#0B0E0F",
        slate: "#12171A",
        raised: "#171D20",
        line: "#1E2528",
        "line-bright": "#2C3639",
        // Ink.
        mineral: "#E8ECEA",
        ash: "#9BA6A8",
        mute: "#6E7A7D",
        // The single accent.
        acid: "#C6FF4A",
        "acid-dim": "#8FB833",
        // Severity data scale (not decoration).
        critical: "#FF3B30",
        high: "#FF8A00",
        medium: "#D9B310",
        low: "#5B8C7A",
        info: "#5A6668",
      },
      fontFamily: {
        display: ["var(--font-display)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      fontSize: {
        label: ["0.6875rem", { lineHeight: "1", letterSpacing: "0.12em" }],
        data: ["0.8125rem", { lineHeight: "1.35" }],
        body: ["0.9375rem", { lineHeight: "1.6" }],
        lede: ["1.0625rem", { lineHeight: "1.55" }],
      },
      borderRadius: { none: "0", chip: "2px", full: "9999px" },
      letterSpacing: { tightest: "-0.045em", display: "-0.035em" },
      transitionTimingFunction: {
        // One entrance curve for the whole system. No bounce anywhere.
        out: "cubic-bezier(0.16, 1, 0.3, 1)",
      },
      keyframes: {
        "trace-x": { from: { transform: "scaleX(0)" }, to: { transform: "scaleX(1)" } },
        "sweep-y": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        "pulse-dot": {
          "0%,100%": { opacity: "1" },
          "50%": { opacity: "0.25" },
        },
      },
      animation: {
        "trace-x": "trace-x 700ms cubic-bezier(0.16,1,0.3,1) forwards",
        "sweep-y": "sweep-y 3.2s linear infinite",
        "pulse-dot": "pulse-dot 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;
