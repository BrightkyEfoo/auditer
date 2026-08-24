import { ImageResponse } from "next/og";

/**
 * The card that appears when the site is shared. Generated rather than a static
 * asset so it can never drift from the art direction, and so the engine count
 * comes from the same source of truth as the page itself.
 *
 * Deliberately built out of the site's own vocabulary — carbon ground, one acid
 * accent, monospace labels, corner ticks — rather than a logo on a gradient. A
 * shared link is often the first thing anyone sees of the product, and a
 * generic card is a wasted first impression.
 */

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt = "auditer — le relevé complet de votre code";

const CARBON = "#0B0E0F";
const MINERAL = "#E8ECEA";
const ACID = "#C6FF4A";
const MUTE = "#6E7A7D";
const LINE = "#1E2528";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: CARBON,
          color: MINERAL,
          padding: 72,
          // The visible 12-column grid, as on the site itself.
          backgroundImage: `repeating-linear-gradient(90deg, ${LINE} 0 1px, transparent 1px 100px)`,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <div
            style={{
              width: 22,
              height: 22,
              border: `2px solid ${ACID}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <div style={{ width: 8, height: 8, background: ACID }} />
          </div>
          <div style={{ fontSize: 30, fontWeight: 700, letterSpacing: "-0.03em" }}>auditer</div>
          <div
            style={{
              marginLeft: "auto",
              fontSize: 17,
              letterSpacing: "0.12em",
              color: MUTE,
            }}
          >
            SYS.AUDITER — 07 PILIERS
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: 92, fontWeight: 700, lineHeight: 1, letterSpacing: "-0.04em" }}>
            Votre code,
          </div>
          <div
            style={{
              fontSize: 92,
              fontWeight: 700,
              lineHeight: 1,
              letterSpacing: "-0.04em",
              paddingLeft: 70,
              color: MUTE,
            }}
          >
            mis sous
          </div>
          <div
            style={{
              fontSize: 92,
              fontWeight: 700,
              lineHeight: 1,
              letterSpacing: "-0.04em",
              color: ACID,
            }}
          >
            instrument.
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: 44,
            borderTop: `1px solid ${LINE}`,
            paddingTop: 24,
            fontSize: 18,
            letterSpacing: "0.1em",
            color: MUTE,
          }}
        >
          <div style={{ display: "flex" }}>SECRETS</div>
          <div style={{ display: "flex" }}>CVE</div>
          <div style={{ display: "flex" }}>SAST</div>
          <div style={{ display: "flex" }}>QUALITÉ</div>
          <div style={{ display: "flex" }}>HYGIÈNE</div>
          <div style={{ display: "flex" }}>PENTEST</div>
          <div style={{ display: "flex" }}>UX</div>
          <div style={{ display: "flex", marginLeft: "auto", color: ACID }}>
            SANDBOX gVisor
          </div>
        </div>
      </div>
    ),
    size,
  );
}
