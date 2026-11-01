// Repository lint gate: `pnpm lint`. Correctness-focused rules, no formatting rules.
//   - TypeScript (src, test, mock, root configs): typescript-eslint recommended, Node globals.
//   - Dashboard (src/api/public/*.js): browser scripts, not modules; they share top-level names via the page.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

// Top-level names app.js defines and builder.js uses (the scripts are loaded in order by index.html).
const DASHBOARD_SHARED = ["$", "api", "el", "ensureToken", "num", "refresh", "tokenInput"];

export default tseslint.config(
  { ignores: ["node_modules/", "dist/", "coverage/"] },

  {
    files: ["**/*.ts"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { globals: globals.node },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }],
    },
  },
  {
    files: ["test/**/*.ts"],
    rules: { "@typescript-eslint/no-explicit-any": "off" }, // test doubles and loosely typed fixtures
  },

  {
    files: ["src/api/public/**/*.js"],
    extends: [js.configs.recommended],
    languageOptions: {
      sourceType: "script",
      globals: { ...globals.browser },
    },
    rules: { "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }] },
  },
  {
    // app.js defines the shared names (and uses its own ones before they are referenced by builder.js).
    files: ["src/api/public/app.js"],
    rules: { "no-unused-vars": ["error", { args: "none", caughtErrors: "none", varsIgnorePattern: `^(${DASHBOARD_SHARED.map((n) => n.replace("$", "\\$")).join("|")})$` }] },
  },
  {
    files: ["src/api/public/builder.js"],
    languageOptions: { globals: Object.fromEntries(DASHBOARD_SHARED.map((n) => [n, "readonly"])) },
  },

  {
    files: ["eslint.config.js"],
    languageOptions: { globals: globals.node },
  },
);
