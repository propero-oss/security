import { defineConfig } from "tsup";
import pkg from "./package.json";

function banner(lines: string[]) {
  if (!lines.length) return "";
  return `/**!${lines.map((line) => `\n * ${line}`).join("")}\n */`;
}

function dateRange(since: number) {
  const now = new Date().getFullYear();
  if (now === since) return since;
  return `${since} - ${now}`;
}

export default defineConfig(({ watch }) => ({
  entry: ["src/index.ts"],
  dts: !watch,
  minify: !watch,
  format: watch ? ["cjs"] : ["esm", "cjs"],
  sourcemap: !watch,
  name: pkg.name,
  onSuccess: watch ? "pnpm run start" : undefined,
  banner: {
    js: banner([pkg.name, pkg.description, `© ${dateRange(pkg.since)} ${pkg.author}`, `@license ${pkg.license}`]),
  },
}));
