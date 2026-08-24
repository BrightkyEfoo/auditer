import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/**
 * tailwind-merge, taught about our custom type scale.
 *
 * Without this it silently produces unreadable UI. Our font sizes are named
 * (`text-label`, `text-data`, `text-body`, `text-lede`) rather than numeric, so
 * the default resolver cannot tell them apart from colours — `text-data` and
 * `text-void` look like the same `text-*` group, the later one wins, and the
 * colour is dropped.
 *
 * That is exactly what happened to every large primary button: the variant set
 * `bg-acid text-void`, the size appended `text-data`, the colour was discarded,
 * and the label fell back to the body's near-white on acid green — around 1.5:1,
 * illegible, on the main call to action of the site. Declaring the scale here
 * fixes it at the source instead of hunting class-order bugs one component at a
 * time.
 *
 * Any font size added to tailwind.config.ts must be added below too.
 */
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["label", "data", "body", "lede"] }],
    },
  },
});

/** Conditional classes with later Tailwind utilities winning over earlier ones. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
