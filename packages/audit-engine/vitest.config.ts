import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
  // Tests import sibling modules via ".js" specifiers (NodeNext style). Vitest's
  // resolver handles the extension rewrite for source .ts files.
  resolve: {
    extensions: [".ts", ".js", ".json"],
  },
});
