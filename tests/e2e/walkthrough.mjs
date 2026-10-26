// End-to-end walkthrough of RateMyAzureSQL (sample data mode) in headless Chromium.
import { chromium } from 'playwright';
import path from 'node:path';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const base = process.env.RMS_URL || 'http://localhost:5220';
const outDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'screenshots');
mkdirSync(outDir, { recursive: true });
const errors = [];
let step = 0;

const browser = await chromium.launch({ executablePath: process.env.PW_EXE || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, colorScheme: 'light' });
page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
page.on('pageerror', e => errors.push('pageerror: ' + e.message));

async function shot(name) {
  step++;
  const file = path.join(outDir, `${String(step).padStart(2, '0')}-${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  console.log('shot', file);
}
async function expectText(text) {
  try {
    await page.getByText(text, { exact: false }).first().waitFor({ timeout: 10000 });
    console.log('  ok:', text);
  } catch (e) {
    await shot('failure');
    console.log('URL:', page.url());
    console.log('PAGE TEXT:', (await page.locator('body').innerText()).slice(0, 2000));
    throw e;
  }
}

// Home
await page.goto(base);
await expectText('How safe is your Azure SQL?');
await shot('home');

// Enter sample data mode -> SQL Database scope
await page.getByRole('button', { name: /Try with sample data/ }).click();
await page.waitForURL(/sql-database/);
await expectText('Choose what to scan');
await page.locator('li.sub-row').first().waitFor();
await page.locator('.sub-count.has').first().waitFor({ timeout: 10000 });
await shot('sqldb-scope');

// Select all relevant and scan
await page.getByRole('button', { name: /Select all with SQL Databases/ }).click();
const scanBtn = page.getByRole('button', { name: /^Scan 2 subscriptions/ });
await scanBtn.waitFor();
await scanBtn.click();
await page.waitForURL(/sql-database\/grades/, { timeout: 20000 });
await expectText('Findings');
const overall = await page.locator('.overall .grade-badge.lg').textContent();
console.log('  SQL Database overall grade:', overall);
if (overall !== 'F') throw new Error('expected overall F, got ' + overall);
const ratingCount = await page.locator('article.rating').count();
console.log('  ratings:', ratingCount);
await shot('sqldb-grades');

// Expand a collapsed rating, a finding fix and a server row
await page.locator('article.rating:not(.open) .rating-row').first().click();
await expectText('Score breakdown');
await page.locator('ul.findings li button.link').first().click();
await page.locator('.fix').first().waitFor();
await page.locator('tr.server-row').first().click();
await page.locator('.policy-detail').first().waitFor();
await expectText('Firewall rules');
await shot('sqldb-grades-expanded');

// Report modal
await page.getByRole('button', { name: /Summary report/ }).first().click();
await expectText('Security & Backup Summary');
await page.getByRole('button', { name: 'Detailed findings' }).click();
await expectText('Detailed Findings');
await shot('sqldb-report');
await page.locator('.modal-head .icon-btn').click();

// Backups step
await page.getByRole('link', { name: /Improve backups/ }).first().click();
await page.waitForURL(/sql-database\/backups/);
await expectText('Improve the backups');
await page.locator('table.db-table tbody tr').first().waitFor();
await expectText('Changes with this plan');
await shot('sqldb-backups');

// Change the plan (Compliance preset), list LTR backups for a database that has them, generate a script
await page.getByRole('button', { name: /^Compliance/ }).click();
await expectText('weekly × 52 weeks');
const ltrBtn = page.getByRole('button', { name: /List the backups that exist/ }).first();
if (await ltrBtn.count()) {
  await ltrBtn.click();
  await page.locator('.ltr-list, .muted:has-text("no long-term backup")').first().waitFor({ timeout: 10000 });
}
await page.getByRole('button', { name: /Generate script for/ }).click();
await expectText('Backup script');
await expectText('Set-AzSqlDatabaseBackupLongTermRetentionPolicy');
await page.getByRole('button', { name: 'Azure CLI' }).click();
await expectText('az sql db ltr-policy set');
await shot('sqldb-backup-script');
await page.locator('.modal-head .icon-btn').click();

// Managed Instance flow
await page.getByRole('link', { name: /Managed Instances/ }).first().click();
await page.waitForURL(/managed-instance/);
await expectText('Choose what to scan');
await page.locator('.sub-count.has').first().waitFor({ timeout: 10000 });
await page.getByRole('button', { name: /Select all with Managed Instances/ }).click();
await page.getByRole('button', { name: /^Scan 2 subscriptions/ }).click();
await page.waitForURL(/managed-instance\/grades/, { timeout: 20000 });
await expectText('Findings');
const miOverall = await page.locator('.overall .grade-badge.lg').textContent();
console.log('  Managed Instance overall grade:', miOverall);
await shot('mi-grades');
await page.getByRole('link', { name: /Improve backups/ }).first().click();
await page.waitForURL(/managed-instance\/backups/);
await page.getByRole('button', { name: /Generate script for/ }).click();
await expectText('Set-AzSqlInstanceDatabaseBackupShortTermRetentionPolicy');
await shot('mi-backup-script');
await page.locator('.modal-head .icon-btn').click();

// Reload keeps sample mode and the scan falls back to scope
await page.reload();
await expectText('Choose what to scan');
await expectText('Sample data');

// Dark theme + mobile
await page.locator('.icon-btn[title="Toggle light / dark"]').click();
await page.setViewportSize({ width: 390, height: 844 });
await page.goto(base + '/sql-database');
await expectText('Choose what to scan');
await shot('mobile-dark');

await browser.close();
if (errors.length) {
  console.error('Browser errors:\n' + errors.join('\n'));
  process.exit(1);
}
console.log('Walkthrough complete, no browser errors.');
