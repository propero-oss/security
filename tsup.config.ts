import { defineConfig } from "tsup";
import pkg from "./package.json";
import fs from "node:fs/promises";

function banner(lines: string[]) {
  if (!lines.length) return "";
  return `/**!${lines.map((line) => `\n * ${line}`).join("")}\n */`;
}

function dateRange(since: number) {
  const now = new Date().getFullYear();
  if (now === since) return since;
  return `${since} - ${now}`;
}

async function allFilesInPath(path: string) {
  return [...await fs.readdir(path)].map(file => `${path}/${file}`);
}

export default defineConfig(async ({ watch }) => {
  const adapters = await allFilesInPath("src/password/adapter");
  const external = Object.keys(pkg.optionalDependencies);
  console.log(adapters);
  return ({
    entry: [
      "src/index.ts",
      ...adapters,
    ],
    target: "node18",
    external,
    dts: !watch,
    minify: !watch,
    format: watch ? ["cjs"] : ["esm", "cjs"],
    sourcemap: !watch,
    name: pkg.name,
    onSuccess: watch ? "pnpm run start" : undefined,
    banner: {
      js: banner([pkg.name, pkg.description, `© ${dateRange(pkg.since)} ${pkg.author}`, `@license ${pkg.license}`]),
    },
  })
});
