import { chromium } from "playwright";

const args = parseArgs(process.argv.slice(2));
const baseUrl = args["base-url"] || "http://127.0.0.1:8000";
const username = args.username || process.env.MONITOR_UI_USERNAME || "admin";
const password = args.password || process.env.MONITOR_UI_PASSWORD;
const headed = Boolean(args.headed);

if (!password) {
  throw new Error("Missing password. Pass --password or set MONITOR_UI_PASSWORD.");
}

const browser = await chromium.launch({ headless: !headed });
const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });

try {
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.fill("#login-username", username);
  await page.fill("#login-password", password);
  await page.click("#login-form button[type='submit']");
  await page.waitForSelector("#app-view:not(.is-hidden)", { timeout: 10000 });

  await expectVisiblePage(page, "overview");
  await clickPage(page, "containers");
  await clickPage(page, "commands");
  await clickPage(page, "audit");
  await clickPage(page, "overview");

  await page.selectOption("#language-select", "zh");
  await page.waitForFunction(() => document.documentElement.lang === "zh-CN");
  await page.selectOption("#language-select", "en");
  await page.waitForFunction(() => document.documentElement.lang === "en");

  const beforeTheme = await page.evaluate(() => document.documentElement.dataset.theme);
  await page.click("#theme-toggle");
  await page.waitForFunction((theme) => document.documentElement.dataset.theme !== theme, beforeTheme);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(250);
  await expectVisiblePage(page, "overview");

  console.log("UI smoke check passed.");
} finally {
  await browser.close();
}

async function clickPage(page, name) {
  await page.click(`[data-page-link="${name}"]`);
  await expectVisiblePage(page, name);
}

async function expectVisiblePage(page, name) {
  await page.waitForFunction(
    (pageName) => {
      const pages = [...document.querySelectorAll("[data-page]")];
      const matching = pages.filter((item) => item.dataset.page === pageName);
      return matching.length > 0 && matching.every((item) => !item.classList.contains("is-hidden"));
    },
    name,
    { timeout: 5000 },
  );
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) continue;
    const key = value.slice(2);
    if (key === "headed") {
      parsed[key] = true;
      continue;
    }
    parsed[key] = values[index + 1];
    index += 1;
  }
  return parsed;
}
