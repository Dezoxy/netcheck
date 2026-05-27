// ESLint flat config (v9) for the netcheck web app.
//
// Rule set intent: catch the bugs TypeScript can't (missing deps in
// useEffect/useMemo, accidental floating promises, unused imports),
// without arguing about style — Prettier owns style.
//
// Bootstrap: deps are pinned in package.json devDependencies. The
// pre-commit hook runs `npx --no-install eslint --fix {files}`.

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";

export default tseslint.config(
  // Files outside src/ (vite.config, etc.) get the bare JS rules only.
  {
    ignores: ["dist/**", "node_modules/**", "../internal/webui/dist/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      // react-hooks/recommended — non-negotiable for React 19's
      // strict-mode behaviour. Misses here become "why did my SSE
      // listener fire twice" bugs at runtime.
      ...reactHooks.configs.recommended.rules,

      // Vite + Fast Refresh wants components exported solo per file.
      // "Constant exports" allow-list keeps type exports from tripping it.
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],

      // Treat unused locals as an error, but allow `_`-prefixed names
      // as an intentional escape hatch (matches Go's blank identifier).
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],

      // `any` should be deliberate. Codex P2 noise on accidental `any`
      // is real — making it an error keeps the SSE parser etc. honest.
      "@typescript-eslint/no-explicit-any": "error",

      // Forbid `// @ts-ignore` without a justification comment.
      "@typescript-eslint/ban-ts-comment": [
        "error",
        { "ts-ignore": "allow-with-description" },
      ],
    },
  },
);
