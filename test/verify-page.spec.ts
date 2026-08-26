import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { expect, test, type Page } from "@playwright/test";

// The repo is "type": "module", so there is no __dirname here.
const here = fileURLToPath(new URL(".", import.meta.url));
const PAGE = resolve(here, "../docs/verify/index.html");
const PAGE_URL = pathToFileURL(PAGE).href;
const EG_VERIFY = resolve(here, "../packages/gate/dist/cli/eg-verify.js");

interface Examples {
  publicKey: string;
  signed: string;
  tampered: string;
}

/** The examples the page ships, read back out of the page itself. */
function embeddedExamples(): Examples {
  const html = readFileSync(PAGE, "utf8");
  const m = /var EXAMPLES = (\{.*?\});/s.exec(html);
  if (!m) throw new Error("docs/verify/index.html has no embedded EXAMPLES");
  return JSON.parse(m[1]!) as Examples;
}

/**
 * Open the page and fail the test if it reaches for anything off-disk. The
 * offline claim is the product; asserting it is not optional.
 */
async function openPage(page: Page): Promise<string[]> {
  const offDisk: string[] = [];
  page.on("request", (r) => {
    if (!r.url().startsWith("file://")) offDisk.push(r.url());
  });
  await page.goto(PAGE_URL);
  return offDisk;
}

async function failures(page: Page) {
  return page.locator("#failures li.failure");
}

test("signed example verifies", async ({ page }) => {
  const offDisk = await openPage(page);

  await page.click("#example-signed");
  await expect(page.locator("#verdict")).toHaveAttribute("data-verdict", "pass");
  await expect(page.locator("#verdict")).toContainText("VERIFIED");
  await expect(await failures(page)).toHaveCount(0);
  await expect(page.locator("#summary")).toHaveText("receipts: 3, allows: 1, denies: 2");

  expect(offDisk, "the page must not request anything off-disk").toEqual([]);
});

test("tampered example fails with exactly one signature break and one chain break", async ({
  page,
}) => {
  const offDisk = await openPage(page);

  await page.click("#example-tampered");
  await expect(page.locator("#verdict")).toHaveAttribute("data-verdict", "fail");

  const all = await failures(page);
  await expect(all).toHaveCount(2);
  await expect(page.locator('#failures li[data-kind="signature"]')).toHaveCount(1);
  await expect(page.locator('#failures li[data-kind="chain"]')).toHaveCount(1);

  // Which line each break lands on is the substance of the demonstration: the
  // edited receipt fails its own signature, and the NEXT receipt's chain link
  // breaks because it commits to the bytes that were replaced.
  await expect(page.locator('#failures li[data-kind="signature"]')).toHaveAttribute(
    "data-line",
    "2",
  );
  await expect(page.locator('#failures li[data-kind="chain"]')).toHaveAttribute("data-line", "3");

  expect(offDisk, "the page must not request anything off-disk").toEqual([]);
});

test("a bad public key is reported as a key problem, not as tampering", async ({ page }) => {
  await openPage(page);
  const ex = embeddedExamples();

  await page.fill("#receipts", ex.signed);
  await page.fill("#pubkey", "not-a-key");
  await page.click("#verify");

  await expect(page.locator("#verdict")).toHaveAttribute("data-verdict", "fail");
  await expect(page.locator('#failures li[data-kind="signature"]')).toHaveCount(0);
});

test("the page agrees with the eg-verify CLI on the same files", async ({ page }) => {
  await openPage(page);
  const ex = embeddedExamples();
  const dir = mkdtempSync(join(tmpdir(), "eg-verify-page-"));

  for (const which of ["signed", "tampered"] as const) {
    const file = join(dir, `${which}.jsonl`);
    writeFileSync(file, ex[which] + "\n");

    // The shipped CLI, on the same bytes.
    let cliOut = "";
    let cliExit = 0;
    try {
      cliOut = execFileSync(
        process.execPath,
        [EG_VERIFY, "--receipts", file, "--pubkey", ex.publicKey],
        { encoding: "utf8" },
      );
    } catch (e) {
      const err = e as { stdout?: string; status?: number };
      cliOut = err.stdout ?? "";
      cliExit = err.status ?? 1;
    }

    await page.fill("#receipts", ex[which]);
    await page.fill("#pubkey", ex.publicKey);
    await page.click("#verify");

    const verdict = await page.locator("#verdict").getAttribute("data-verdict");
    const summary = (await page.locator("#summary").textContent()) ?? "";
    const pageBreaks = await page.locator("#failures li.failure").allTextContents();

    // Same overall answer.
    expect(verdict, `${which}: verdict must match the CLI`).toBe(
      cliOut.includes("RESULT: VERIFIED") ? "pass" : "fail",
    );
    expect(cliExit === 0 ? "pass" : "fail").toBe(verdict);

    // Same counts, in the CLI's own wording.
    expect(cliOut, `${which}: counts must match`).toContain(summary.trim());

    // Same breaks, line for line and message for message.
    const cliBreaks = cliOut
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => /^line \d+: /.test(l));
    expect(pageBreaks.map((b) => b.trim())).toEqual(cliBreaks);
  }
});
