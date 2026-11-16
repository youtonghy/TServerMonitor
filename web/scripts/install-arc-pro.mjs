#!/usr/bin/env node
// Installs the licensed Arc Pro components listed in arc-pro.json into src/components/arc-pro/.
//
// Arc Pro source must never be committed (src/components/arc-pro/ is git-ignored), so CI and every
// developer run this once after `pnpm install`:
//
//   ARC_PRO_TOKEN=... pnpm arc:pro        (or put ARC_PRO_TOKEN=... in web/.env.local)
//
// Steps:
//   1. `npx shadcn@latest add @uiarc-pro/<name>...` with the token in the environment. The @uiarc-pro registry
//      in components.json sends it as `Authorization: Bearer ${ARC_PRO_TOKEN}`. Free Arc dependencies land in
//      the normal free folder (src/components/arc/) and existing free files are left alone.
//   2. Each Pro item's folder is moved from src/components/arc/<name> (components) or
//      src/components/arc/blocks/<name> (blocks) to src/components/arc-pro/<name>.
//   3. Relative imports in the moved files that pointed into the Arc tree (for example "../lib/motion-tokens"
//      or "../../segmented-control/segmented-control") are rewritten to "@/components/arc/..." (or
//      "@/components/arc-pro/..." when the target is another Pro item), so they resolve from the new folder.
//
// `--relink-only` skips step 1 and 2 and only rewrites imports in src/components/arc-pro/, which is useful
// when the Pro files were copied in by hand.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const freeDir = path.join(root, "src/components/arc");
const proDir = path.join(root, "src/components/arc-pro");
const relinkOnly = process.argv.includes("--relink-only");

function fail(message) {
  console.error(`arc:pro: ${message}`);
  process.exit(1);
}

function readNames() {
  const file = path.join(root, "arc-pro.json");
  let names;
  try {
    names = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`cannot read ${path.relative(root, file)}: ${error.message}`);
  }
  if (!Array.isArray(names) || names.some(name => typeof name !== "string" || !/^[a-z0-9-]+$/.test(name))) {
    fail("arc-pro.json must be a JSON array of component names, for example [\"radar-chart\"]");
  }
  return names;
}

/** ARC_PRO_TOKEN from the environment, else from web/.env.local. The value is never printed. */
function readToken() {
  if (process.env.ARC_PRO_TOKEN) return process.env.ARC_PRO_TOKEN;
  const envFile = path.join(root, ".env.local");
  if (existsSync(envFile)) {
    for (const line of readFileSync(envFile, "utf8").split(/\r?\n/)) {
      const match = line.match(/^\s*(?:export\s+)?ARC_PRO_TOKEN\s*=\s*(.*)\s*$/);
      if (match) {
        const value = match[1].replace(/^(['"])(.*)\1$/, "$2").trim();
        if (value) return value;
      }
    }
  }
  return null;
}

function install(names, token) {
  const npx = process.platform === "win32" ? "npx.cmd" : "npx";
  const args = ["-y", "shadcn@latest", "add", ...names.map(name => `@uiarc-pro/${name}`), "-y"];
  console.log(`arc:pro: installing ${names.join(", ")}`);
  const result = spawnSync(npx, args, { cwd: root, stdio: "inherit", env: { ...process.env, ARC_PRO_TOKEN: token } });
  if (result.error) fail(`could not run shadcn: ${result.error.message}`);
  if (result.status !== 0) fail(`shadcn exited with code ${result.status}. Check that ARC_PRO_TOKEN is valid.`);
}

/** Moves each Pro item's folder out of the free tree. */
function relocate(names) {
  mkdirSync(proDir, { recursive: true });
  for (const name of names) {
    const candidates = [path.join(freeDir, name), path.join(freeDir, "blocks", name)];
    const source = candidates.find(dir => existsSync(dir) && statSync(dir).isDirectory());
    const target = path.join(proDir, name);
    if (!source) {
      if (existsSync(target)) continue; // Already relocated by an earlier run.
      fail(`shadcn did not create a folder for ${name} (looked in ${candidates.map(c => path.relative(root, c)).join(" and ")})`);
    }
    rmSync(target, { recursive: true, force: true });
    renameSync(source, target);
  }
  const blocks = path.join(freeDir, "blocks");
  if (existsSync(blocks) && readdirSync(blocks).length === 0) rmSync(blocks, { recursive: true });
}

const IMPORT = /(\bfrom\s+|\bimport\s*\(\s*|\bimport\s+)(["'])(\.\.\/[^"']+)\2/g;

/** Rewrites "../x" imports that escape the item folder to the alias of the Arc tree they meant. */
function relink(names) {
  const proItems = new Set(existsSync(proDir) ? readdirSync(proDir) : []);
  let changed = 0;
  for (const name of names) {
    const dir = path.join(proDir, name);
    if (!existsSync(dir)) fail(`missing ${path.relative(root, dir)}`);
    for (const file of readdirSync(dir)) {
      if (!/\.(tsx?|css)$/.test(file)) continue;
      const full = path.join(dir, file);
      const text = readFileSync(full, "utf8");
      const next = text.replace(IMPORT, (_all, lead, quote, spec) => {
        const rest = spec.replace(/^(\.\.\/)+/, "").replace(/^blocks\//, "");
        const first = rest.split("/")[0];
        const base = proItems.has(first) && !existsSync(path.join(freeDir, first)) ? "@/components/arc-pro" : "@/components/arc";
        return `${lead}${quote}${base}/${rest}${quote}`;
      });
      if (next !== text) {
        writeFileSync(full, next);
        changed += 1;
      }
    }
  }
  console.log(`arc:pro: relinked imports in ${changed} file(s)`);
}

const names = readNames();
if (!relinkOnly) {
  const token = readToken();
  if (!token) {
    fail("ARC_PRO_TOKEN is not set. Export it or add ARC_PRO_TOKEN=<token> to web/.env.local (git-ignored), then run `pnpm arc:pro` again.");
  }
  install(names, token);
  relocate(names);
}
relink(names);
console.log(`arc:pro: done. Pro components are in ${path.relative(root, proDir)}/ (git-ignored).`);
