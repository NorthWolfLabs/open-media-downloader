// omd-browser-protocol: 2 (origin page storage restore/export). The engine reads
// this marker from the verified kit before sending account page storage.
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { frames } from './protocol.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
const spawn = childProcess.spawn;
childProcess.spawn = (file, args, options = {}) => spawn(file, args, { ...options, detached: false });
syncBuiltinESMExports();
const { chromium } = await import('playwright-core');
let browser, context, page, previous = 0, stage = 'protocol';
let controlSequence = 0;
const controls = new Map();
let nativeBrowser;
async function launchWindows(command) {
  // libuv's anonymous stdio pipes use a global name that AppContainer denies.
  // Keep native handles inherited, and connect Playwright to the random CDP
  // listener inside this same no-network-capability AppContainer instead.
  const profile = await fs.mkdtemp(path.join(process.cwd(), 'chromium-'));
  nativeBrowser = spawn(command.executable, [
    ...(command.headed ? [] : ['--headless']), '--no-sandbox', '--no-zygote', '--disable-gpu', '--disable-notifications', '--disable-quic',
    '--disable-background-networking', '--disable-breakpad', '--disable-component-update',
    '--disable-default-apps', '--disable-extensions', '--disable-sync', '--no-first-run',
    '--no-default-browser-check', '--metrics-recording-only', '--password-store=basic',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, `--proxy-server=${command.proxy}`,
    '--proxy-bypass-list=<-loopback>', `--ignore-certificate-errors-spki-list=${command.spki}`,
    'about:blank',
  ], { detached: false, windowsHide: !command.headed, stdio: ['ignore', 'ignore', 'inherit'] });
  let failure;
  nativeBrowser.on('error', () => { failure = true; });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (failure || nativeBrowser.exitCode !== null) throw new Error('browser_start_failed');
    const active = await fs.readFile(path.join(profile, 'DevToolsActivePort'), 'utf8').catch(() => '');
    const [port, endpoint] = active.trim().split(/\r?\n/);
    if (/^[0-9]{1,5}$/.test(port) && +port > 0 && +port < 65536 && /^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(endpoint)) {
      return chromium.connectOverCDP(`ws://127.0.0.1:${port}${endpoint}`, { timeout: Math.max(1, deadline - Date.now()) });
    }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('browser_start_timeout');
}
async function execute(command) {
  if (command.id <= previous) throw new Error('sequence');
  previous = command.id;
  if (command.op === 'start') {
    if (browser) throw new Error('already_started');
    stage = 'launch';
    const launchOptions = { executablePath: command.executable, headless: !command.headed, chromiumSandbox: false,
      timeout: 15000, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false,
      proxy: { server: command.proxy, username: command.username, password: '', bypass: '<-loopback>' },
      args: ['--disable-gpu', '--disable-notifications', '--disable-crash-reporter', '--disable-crashpad-for-testing', '--no-zygote', '--disable-quic', `--ignore-certificate-errors-spki-list=${command.spki}`] };
    const contextOptions = { acceptDownloads: false, serviceWorkers: 'block',
      ...(process.platform === 'win32' ? { proxy: { server: command.proxy, username: command.username, password: '', bypass: '<-loopback>' } } : {}),
      // Only the broker's ephemeral SPKI is trusted by the launch configuration.
      // The engine verifies the actual remote certificate on every request.
      viewport: { width: 960, height: 640 } };
    if (command.origins?.length) {
      if (command.headed) throw new Error('invalid_start');
      // Applied while the context is created, before any page script can run.
      contextOptions.storageState = { cookies: [], origins: command.origins };
    }
    if (command.headed && process.platform !== 'win32') {
      // A fresh profile creates a normal visible browser window at launch. Its
      // lifetime is still limited to this session's private work directory.
      const profile = await fs.mkdtemp(path.join(process.cwd(), 'signin-'));
      context = await chromium.launchPersistentContext(profile, {...launchOptions, ...contextOptions});
      browser = context.browser();
    } else {
      browser = process.platform === 'win32' ? await launchWindows(command) : await chromium.launch(launchOptions);
      context = await browser.newContext(contextOptions);
    }
    stage = 'context';
    context.setDefaultTimeout(10000);
    context.setDefaultNavigationTimeout(15000);
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.protocol !== 'https:' || url.username || url.password) await route.abort('blockedbyclient');
      else await route.continue();
    });
    await context.routeWebSocket('**/*', socket => socket.close());
    await context.addCookies(command.cookies);
    page = context.pages()[0] ?? await context.newPage();
    context.on('page', popup => { if (popup !== page) void popup.close(); });
    stage = 'navigation';
    await page.goto(command.url, { waitUntil: 'domcontentloaded' });
    if (command.headed) await page.bringToFront();
    return { ready: true };
  }
  if (!page) throw new Error('not_started');
  stage = 'interaction';
  const locator = () => page.locator(`css=${command.selector}`);
  switch (command.op) {
    case 'navigate': await page.goto(command.url, { waitUntil: 'domcontentloaded' }); break;
    case 'wait': await locator().waitFor({ state: 'visible' }); break;
    case 'click': await locator().click(); break;
    case 'fill': await locator().fill(command.text); break;
    case 'select': await locator().selectOption(command.value); break;
    case 'press': await page.keyboard.press(command.key); break;
    case 'pointer': await page.mouse.click(command.x, command.y); break;
    case 'type': await page.keyboard.insertText(command.text); break;
    case 'scroll': await page.mouse.wheel(0, command.delta); break;
    case 'control': {
      const control = controls.get(command.control);
      if (!control) throw new Error('stale_control');
      if (command.action.kind === 'fill') await control.fill(command.action.text);
      else if (command.action.kind === 'select') await control.selectOption(command.action.value);
      else {
        const externalTarget = await control.evaluate(element => element instanceof HTMLAnchorElement && element.target === '_blank' ? element.href : null);
        if (externalTarget) {
          const url = new URL(externalTarget);
          if (url.protocol !== 'https:' || url.username || url.password) throw new Error('invalid_link');
          const response = await page.goto(url.href, { waitUntil: 'domcontentloaded' });
          if (response && response.status() >= 400) throw new Error('link_unavailable');
        } else await control.click();
      }
      break;
    }
    case 'frame': {
      for (const handle of controls.values()) await handle.dispose();
      controls.clear();
      const handles = await page.locator('input:not([type=hidden]),textarea,select,button,a[href],[role=button]').elementHandles();
      const fields = [];
      for (const handle of handles.slice(0, 200)) {
        if (!await handle.isVisible()) { await handle.dispose(); continue; }
        const field = await handle.evaluate(element => {
          const input = element instanceof HTMLInputElement;
          const password = input && element.type === 'password';
          const kind = element instanceof HTMLAnchorElement ? 'link' : element instanceof HTMLSelectElement ? 'select' : input && ['checkbox', 'radio'].includes(element.type) ? 'check' : (input && !['submit', 'button', 'reset', 'file', 'image'].includes(element.type) || element instanceof HTMLTextAreaElement) ? (password ? 'password' : 'text') : element instanceof HTMLButtonElement && element.type === 'submit' && element.form ? 'submit' : 'button';
          const labelledBy = (element.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean).map(id => document.getElementById(id)?.textContent ?? '').join(' ').trim();
          const label = (element.getAttribute('aria-label') || labelledBy || element.labels?.[0]?.innerText || element.getAttribute('title') || (['button', 'submit', 'link'].includes(kind) ? element.innerText : '') || element.getAttribute('placeholder') || (kind === 'select' ? 'Select an option' : element.getAttribute('name') || element.tagName)).slice(0, 1024);
          return { kind, label, disabled: !!element.disabled, value: !password && ['text', 'select'].includes(kind) ? String(element.value ?? '').slice(0, 16384) : '', entered: password && !!element.value, checked: !!element.checked,
            options_truncated: element instanceof HTMLSelectElement && element.options.length > 200,
            options: element instanceof HTMLSelectElement ? Array.from(element.options).slice(0, 200).map(option => ({ value: option.value.slice(0, 4096), label: option.text.slice(0, 1024) })) : [] };
        });
        const id = `control-${++controlSequence}`;
        controls.set(id, handle); fields.push({ id, ...field });
      }
      for (const handle of handles.slice(200)) await handle.dispose();
      const bytes = await page.screenshot({ type: 'png', timeout: 10000 });
      if (bytes.length > 2 * 1024 * 1024) throw new Error('output_budget');
      return { png: bytes.toString('base64'), width: 960, height: 640, origin: new URL(page.url()).origin, controls: fields, controls_truncated: handles.length > 200 || fields.some(field => field.options_truncated) };
    }
    case 'snapshot': return await page.evaluate(() => ({
      url: location.href,
      title: document.title.slice(0, 1024),
      text: (document.body?.innerText ?? '').slice(0, 256 * 1024),
      links: Array.from(document.querySelectorAll('a[href]')).slice(0, 1000).map(a => ({ text: a.innerText.slice(0, 1024), url: a.href.slice(0, 4096) })),
      truncated: (document.body?.innerText.length ?? 0) > 256 * 1024 || document.querySelectorAll('a[href]').length > 1000 || Array.from(document.querySelectorAll('a[href]')).slice(0, 1000).some(a => a.innerText.length > 1024 || a.href.length > 4096),
    }));
    case 'cookies': return { cookies: await context.cookies() };
    case 'storage': {
      const state = await context.storageState();
      return { origins: state.origins.slice(0, 64).map(entry => ({ origin: entry.origin, localStorage: entry.localStorage.slice(0, 256).map(({ name, value }) => ({ name, value })) })) };
    }
    case 'close': await context.close(); await browser.close(); page = undefined; return { closed: true };
    default: throw new Error('invalid_command');
  }
  return { ready: true };
}
try {
  for await (const command of frames(process.stdin)) {
    try {
      const response = JSON.stringify({ id: command.id, result: await execute(command) });
      if (Buffer.byteLength(response) > 4 * 1024 * 1024 - 1) throw new Error('output_budget');
      await new Promise((resolve, reject) => process.stdout.write(response + '\n', error => error ? reject(error) : resolve()));
      if (command.op === 'close') break;
    } catch (error) {
      // Playwright errors contain page text, URLs, selectors, and input values.
      // Never send their message/stack to the engine or diagnostics.
      const reason = String(error.message).match(/net::(ERR_[A-Z_]{1,64})\b/)?.[1] ?? 'operation_failed';
      process.stdout.write(JSON.stringify({ id: command.id, error: 'browser_operation_failed', stage, reason }) + '\n');
      if (command.op === 'start' || command.op === 'close') break;
    }
  }
} catch { process.stderr.write('OMD browser protocol rejected\n'); }
finally {
  if (browser) await browser.close().catch(() => {});
  // The outer Rust job also kills every descendant on errors or cancellation.
  if (nativeBrowser && nativeBrowser.exitCode === null) nativeBrowser.kill();
}
