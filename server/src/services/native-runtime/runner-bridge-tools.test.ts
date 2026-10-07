import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { materializeAsset } from "./runtime-context.js";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { executeWorkspaceTool, readAssignedSkill, runnerBridgeDefinitions, workspaceCommandSandboxAvailable } from "./runner-bridge-tools.js";
const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });
const root = async () => { const directory = await mkdtemp(join(tmpdir(), "dot-bridge-")); roots.push(directory); return directory; };
const authorize = async () => {};
describe("Runner workspace bridge", () => {
  it("guards new writes, existing content, traversal and symlinks", async () => {
    const directory = await root(), outside = await root();
    const result = await executeWorkspaceTool(directory, "workspace_write", { path: "hello.txt", text: "hello 🌍", expectedSha256: null }, authorize) as any;
    expect(result.byteSize).toBe(Buffer.byteLength("hello 🌍"));
    expect(await executeWorkspaceTool(directory, "workspace_read", { path: "hello.txt" }, authorize)).toMatchObject({ text: "hello 🌍", sha256: result.sha256 });
    await expect(executeWorkspaceTool(directory, "workspace_write", { path: "hello.txt", text: "overwrite", expectedSha256: null }, authorize)).rejects.toThrow();
    await expect(executeWorkspaceTool(directory, "workspace_write", { path: "hello.txt", text: "overwrite", expectedSha256: "0".repeat(64) }, authorize)).rejects.toThrow("conflict");
    await executeWorkspaceTool(directory, "workspace_write", { path: "hello.txt", text: "updated", expectedSha256: result.sha256 }, authorize);
    await expect(executeWorkspaceTool(directory, "workspace_read", { path: "../hello.txt" }, authorize)).rejects.toThrow();
    await writeFile(join(outside, "private.txt"), "PRIVATE");
    await symlink(outside, join(directory, "outside"));
    await expect(executeWorkspaceTool(directory, "workspace_read", { path: "outside/private.txt" }, authorize)).rejects.toThrow("symlink");
  });
  it.skipIf(!workspaceCommandSandboxAvailable())("runs useful commands but denies files outside the workspace and injected credentials", async () => {
    const directory = await root(), outside = await root();
    const secret = join(outside, "private.txt"); await writeFile(secret, "PRIVATE");
    const success = await executeWorkspaceTool(directory, "workspace_run", { program: "/bin/sh", args: ["-c", "printf hello > output.txt; printf '%s' \"${PAPERCLIP_SECRETS_MASTER_KEY-unset}\"" ] }, authorize);
    expect(success).toMatchObject({ exitCode: 0, output: "unset", stopped: null });
    expect(await readFile(join(directory, "output.txt"), "utf8")).toBe("hello");
    const read = await executeWorkspaceTool(directory, "workspace_run", { program: "/bin/cat", args: [secret] }, authorize);
    expect(read).toMatchObject({ exitCode: 1 }); expect(String((read as any).output)).not.toContain("PRIVATE");
    const write = await executeWorkspaceTool(directory, "workspace_run", { program: "/bin/sh", args: ["-c", 'printf stolen > "$1"', "sh", secret] }, authorize);
    expect(write).toMatchObject({ exitCode: 1 }); expect(await readFile(secret, "utf8")).toBe("PRIVATE");
  });
  it.skipIf(!workspaceCommandSandboxAvailable())("stops its owned process on authority loss and bounds output", async () => {
    const directory = await root(); let calls = 0;
    const result = await executeWorkspaceTool(directory, "workspace_run", { program: "/bin/sleep", args: ["20"] }, async () => { if (++calls > 2) throw new Error("revoked"); });
    expect(result).toMatchObject({ stopped: "authority_revoked" });
    const large = await executeWorkspaceTool(directory, "workspace_run", { program: "/bin/sh", args: ["-c", "yes x | head -c 50000"] }, authorize) as any;
    expect(large.truncated).toBe(true); expect(Buffer.byteLength(large.output)).toBeLessThanOrEqual(24000);
  });
  it("reads only a pinned skill file and detects tampering", async () => {
    const bundle = await materializeAsset([{ path: "SKILL.md", content: Buffer.from("# Assigned skill\nUse the pinned instructions."), mode: 0o444 }]);
    const context = { skills: [{ key: "assigned", runtimeName: "assigned", versionId: "version-1", bundle }] } as any;
    expect(await readAssignedSkill(context, { skill: "assigned" })).toMatchObject({ versionId: "version-1", text: "# Assigned skill\nUse the pinned instructions." });
    await expect(readAssignedSkill(context, { skill: "not-assigned" })).rejects.toThrow("not_assigned");
    await expect(readAssignedSkill(context, { skill: "assigned", path: "../private" })).rejects.toThrow();
    await expect(readAssignedSkill(context, { skill: "assigned", path: "not-pinned.txt" })).rejects.toThrow("not_pinned");
    await expect(readAssignedSkill({ ...context, skills: [{ ...context.skills[0], bundle: { ...bundle, manifestDigest: createHash("sha256").update("different").digest("hex") } }] }, { skill: "assigned" })).rejects.toThrow("manifest_digest");
  });

  it("advertises only available tools in the current work mode", () => {
    const tools = runnerBridgeDefinitions({ workspace: false, skills: false, api: false, mode: "ask" }).map(tool => tool.name);
    expect(tools).toEqual(["get_identity", "list_people"]);
    expect(runnerBridgeDefinitions({ workspace: true, skills: true, api: true, mode: "planning" }).map(tool => tool.name)).not.toContain("workspace_run");
  });
});
