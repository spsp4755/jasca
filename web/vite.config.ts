import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { writeFileSync } from "node:fs";

// The Go binary embeds dist/. dist/.keep is tracked (root .gitignore: web/dist/* + !web/dist/.keep) so `go build`
// works before the first web build; emptyOutDir deletes it, so it is written back after every build.
const keep = { name: "jasca-dist-keep", closeBundle: () => writeFileSync("dist/.keep", "") };

export default defineConfig({
  plugins: [react(), keep],
  server: { proxy: { "/api": "http://127.0.0.1:18300", "/healthz": "http://127.0.0.1:18300" } },
  preview: { proxy: { "/api": "http://127.0.0.1:18300", "/healthz": "http://127.0.0.1:18300" } },
  build: { outDir: "dist", emptyOutDir: true },
});
