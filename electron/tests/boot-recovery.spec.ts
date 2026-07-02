import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Real boot-recovery e2e: the app starts with Docker "down" (a fake docker CLI
// on PATH fails `docker version`), lands on the docker-missing screen, the
// daemon "comes back", and one Check-again click must carry the boot all the
// way to READY — orphan cleanup, image check, container start and the
// /capabilities health poll all run for real, with `docker run` booting the
// actual web server (docker/web/server.py) standalone on the mapped port.
//
// The unit tests cover the boot state TABLE; the smoke spec seeds screens
// statically. This is the only test that drives the real retry wiring
// (ipcMain startup:retry -> startup() -> loadURL -> BOOT.READY).
//
// POSIX-only: the fake docker is a /bin/sh script. On Windows the same wiring
// is main-process JS shared with the platforms tested here; desktop.yml's
// Windows lane still runs the unit + smoke suites.
const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeDockerDir = path.join(appRoot, "tests", "fake-docker");
const serverPy = path.resolve(appRoot, "..", "docker", "web", "server.py");

test.skip(process.platform === "win32", "fake docker CLI is POSIX sh");

test("docker-missing recovers to READY after the daemon comes back", async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "bomlens-boot-"));
  const stateFile = path.join(scratch, "docker-state");
  const outDir = path.join(scratch, "out");
  fs.mkdirSync(outDir);
  fs.writeFileSync(stateFile, "down");

  const app = await electron.launch({
    args: [appRoot],
    env: {
      ...process.env,
      PATH: `${fakeDockerDir}${path.delimiter}${process.env.PATH}`,
      FAKE_DOCKER_STATE: stateFile,
      FAKE_DOCKER_RUN_DIR: scratch,
      FAKE_SERVER: serverPy,
      FAKE_OUTPUT_DIR: outDir,
      SBOM_OUTPUT_DIR: outDir, // keep defaultOutputDir() away from ~/sbom-output
      SBOM_LANG: "en",
    },
  });
  try {
    const win = await app.firstWindow();

    // Docker down -> the real startup() lands on the docker-missing screen.
    await expect(win.locator("#check-again")).toBeVisible({ timeout: 20_000 });

    // Daemon "comes back": flip the fake CLI's state, then retry once.
    fs.writeFileSync(stateFile, "up");
    await win.locator("#check-again").click();

    // The retry must carry the boot to the container origin: status screen ->
    // orphan cleanup -> image present -> fake `docker run` boots server.py ->
    // health poll passes -> loadURL(http://127.0.0.1:<port>).
    await expect
      .poll(() => win.url(), { timeout: 30_000 })
      .toMatch(/^http:\/\/127\.0\.0\.1:\d+/);

    // The startup log must record the full recovery path.
    const userData = await app.evaluate(({ app: a }) => a.getPath("userData"));
    const startupLog = path.join(userData, "startup.log");
    await expect
      .poll(() => {
        try {
          return fs.readFileSync(startupLog, "utf8");
        } catch {
          return "";
        }
      })
      .toContain("boot state: ready");
    const log = fs.readFileSync(startupLog, "utf8");
    expect(log).toContain("boot state: failed-docker");

    // The spawned server must be alive while the app runs...
    const pid = Number(fs.readFileSync(path.join(scratch, "server.pid"), "utf8").trim());
    expect(() => process.kill(pid, 0)).not.toThrow();

    await app.close();

    // ...and shutdown() must have stopped it (fake `docker stop` kills it).
    await expect
      .poll(() => {
        try {
          process.kill(pid, 0);
          return "alive";
        } catch {
          return "stopped";
        }
      })
      .toBe("stopped");
  } finally {
    try {
      await app.close();
    } catch {
      /* already closed above on the happy path */
    }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
