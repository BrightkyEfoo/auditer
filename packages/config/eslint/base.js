// Flat ESLint config shared across the monorepo.
// Kept intentionally light — type-aware linting is opt-in per package to avoid
// slow project-service resolution across every workspace.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
  {
    ignores: ["dist/**", ".next/**", "node_modules/**", "**/*.generated.*"],
  },
);
