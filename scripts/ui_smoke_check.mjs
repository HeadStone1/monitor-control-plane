const { chromium } = await loadPlaywright();

const args = parseArgs(process.argv.slice(2));
const baseUrl = args["base-url"] || "http://127.0.0.1:8000";
const username = args.username || process.env.MONITOR_UI_USERNAME || "admin";
const password = args.password || process.env.MONITOR_UI_PASSWORD;
const headed = Boolean(args.headed);
const browserExecutable = process.env.MONITOR_BROWSER_EXECUTABLE;
const screenshotPath = process.env.MONITOR_UI_SCREENSHOT;

if (!password) {
  throw new Error("Missing password. Pass --password or set MONITOR_UI_PASSWORD.");
}

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch (error) {
    const modulePath = process.env.MONITOR_PLAYWRIGHT_MODULE;
    if (!modulePath) throw error;
    return import(modulePath);
  }
}

const browser = await chromium.launch({
  headless: !headed,
  ...(browserExecutable ? { executablePath: browserExecutable } : {}),
});
const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });

try {
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.fill("#login-username", username);
  await page.fill("#login-password", password);
  await page.click("#login-form button[type='submit']");
  await page.waitForSelector("#app-view:not(.is-hidden)", { timeout: 10000 });

  await expectVisiblePage(page, "overview");
  const metricRanges = await page.locator("#metric-range option").evaluateAll((options) => (
    options.map((option) => option.value)
  ));
  assertEqual(
    JSON.stringify(metricRanges),
    JSON.stringify(["1h", "24h", "7d", "15d", "30d", "60d", "90d"]),
    "metric range options",
  );
  await page.selectOption("#metric-range", "90d");
  await page.waitForFunction(() => document.querySelector("#metric-range")?.value === "90d");
  await page.click('[data-metric="memory"]');
  await page.waitForFunction(() => document.querySelector('[data-metric="memory"]')?.getAttribute("aria-pressed") === "false");
  await page.click('[data-metric="memory"]');
  await page.waitForFunction(() => document.querySelector('[data-metric="memory"]')?.getAttribute("aria-pressed") === "true");
  const chartSize = await page.locator("#metric-chart").evaluate((canvas) => ({
    cssWidth: canvas.getBoundingClientRect().width,
    cssHeight: canvas.getBoundingClientRect().height,
    pixelWidth: canvas.width,
    pixelHeight: canvas.height,
  }));
  if (chartSize.cssWidth < 280 || chartSize.cssHeight < 220 || chartSize.pixelWidth < chartSize.cssWidth) {
    throw new Error(`Metric chart has invalid dimensions: ${JSON.stringify(chartSize)}`);
  }
  if (screenshotPath) {
    await page.screenshot({ path: screenshotPath, fullPage: true });
  }
  await clickPage(page, "containers");
  await clickPage(page, "commands");
  await clickPage(page, "audit");
  await clickPage(page, "admin");
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
  await page.click("#mobile-nav-toggle");
  await page.waitForSelector("#app-view:not(.sidebar-collapsed)");
  await clickPage(page, "containers");
  await page.waitForSelector("#app-view.sidebar-collapsed");
  await page.click("#mobile-nav-toggle");
  await clickPage(page, "overview");
  const hasHorizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  assertEqual(hasHorizontalOverflow, false, "mobile horizontal overflow");

  console.log("UI smoke check passed.");
} finally {
  await browser.close();
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, received ${actual}`);
  }
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
