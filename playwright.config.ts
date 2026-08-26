import { defineConfig, devices } from "@playwright/test";

// The page under test is a single file opened from disk. There is no server
// here on purpose: a dev server would prove the page works when something is
// serving it, which is the one condition the page is designed not to need.
export default defineConfig({
  testDir: "./test",
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  use: { ...devices["Desktop Chrome"] },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
