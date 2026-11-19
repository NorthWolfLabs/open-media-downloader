// Only engine-created commands enter this channel. Page content never becomes
// JavaScript, launch arguments, executable paths, or filesystem paths.
export const MAX_FRAME = 2 * 1024 * 1024;
// Page storage restored only into its own serialized HTTPS origin.
function validateOrigins(origins) {
  if (!Array.isArray(origins) || origins.length < 1 || origins.length > 16) throw new Error('invalid_start');
  const seen = new Set();
  for (const entry of origins) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).some(key => !['origin', 'localStorage'].includes(key))) throw new Error('invalid_start');
    if (typeof entry.origin !== 'string' || seen.has(entry.origin)) throw new Error('invalid_start');
    const url = new URL(entry.origin);
    if (url.protocol !== 'https:' || url.origin !== entry.origin) throw new Error('invalid_start');
    seen.add(entry.origin);
    if (!Array.isArray(entry.localStorage) || entry.localStorage.length > 256) throw new Error('invalid_start');
    for (const item of entry.localStorage) {
      if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).some(key => !['name', 'value'].includes(key)) || typeof item.name !== 'string' || typeof item.value !== 'string' || !item.name || item.name.length > 1024) throw new Error('invalid_start');
    }
  }
}
export function validateCommand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Number.isSafeInteger(value.id) || value.id < 1) throw new Error('invalid_command');
  const fields = {
    start: ['executable', 'proxy', 'username', 'spki', 'url', 'cookies', 'headed', 'origins'],
    navigate: ['url'], wait: ['selector'], click: ['selector'], fill: ['selector', 'text'],
    select: ['selector', 'value'], press: ['key'], pointer: ['x', 'y'], type: ['text'],
    scroll: ['delta'], control: ['control', 'action'], snapshot: [], frame: [], cookies: [], storage: [], close: [],
  }[value.op];
  if (!fields || Object.keys(value).some(key => !['id', 'op', ...fields].includes(key))) throw new Error('invalid_command');
  for (const key of ['url', 'selector', 'text', 'value', 'executable', 'username', 'proxy']) {
    if (value[key] !== undefined && (typeof value[key] !== 'string' || value[key].length > (key === 'text' ? 16384 : 4096))) throw new Error('invalid_command');
  }
  if (['navigate', 'start'].includes(value.op)) {
    const url = new URL(value.url);
    if (url.protocol !== 'https:' || url.username || url.password) throw new Error('invalid_url');
  }
  if (['wait', 'click', 'fill', 'select'].includes(value.op) && (!value.selector || value.selector.length > 1024 || value.selector.includes('>>'))) throw new Error('invalid_selector');
  if (['type', 'fill'].includes(value.op) && typeof value.text !== 'string') throw new Error('invalid_command');
  if (value.op === 'select' && typeof value.value !== 'string') throw new Error('invalid_command');
  if (value.op === 'press' && !['Tab', 'Shift+Tab', 'Enter', 'Escape', 'Backspace', 'Delete', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(value.key)) throw new Error('invalid_key');
  if (value.op === 'pointer' && (!Number.isInteger(value.x) || !Number.isInteger(value.y) || value.x < 0 || value.x >= 960 || value.y < 0 || value.y >= 640)) throw new Error('invalid_pointer');
  if (value.op === 'scroll' && (!Number.isInteger(value.delta) || Math.abs(value.delta) > 1280)) throw new Error('invalid_scroll');
  if (value.op === 'control') {
    if (typeof value.control !== 'string' || !/^control-[0-9]{1,8}$/.test(value.control) || !value.action || typeof value.action !== 'object') throw new Error('invalid_control');
    const action = value.action;
    if (!['click', 'fill', 'select'].includes(action.kind) || Object.keys(action).some(key => !['kind', ...(action.kind === 'fill' ? ['text'] : action.kind === 'select' ? ['value'] : [])].includes(key))) throw new Error('invalid_control');
    const text = action.kind === 'fill' ? action.text : action.kind === 'select' ? action.value : '';
    if (typeof text !== 'string' || text.length > 16384) throw new Error('invalid_control');
  }
  if (value.op === 'start') {
    if(value.headed !== undefined && typeof value.headed !== 'boolean')throw new Error('invalid_start');
    if (typeof value.spki !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value.spki)) throw new Error('invalid_start');
    if (!value.executable || !/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(value.proxy) || !/^[a-f0-9]{64}$/.test(value.username) || !Array.isArray(value.cookies) || value.cookies.length > 512) throw new Error('invalid_start');
    if (value.origins !== undefined) validateOrigins(value.origins);
  }
  return value;
}

// Byte-count before decoding avoids partial UTF-8 corruption and unbounded
// readline allocations. Requests execute serially; no detached pending work.
export async function* frames(stream) {
  let pending = Buffer.alloc(0);
  for await (const chunk of stream) {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > MAX_FRAME) throw new Error('input_budget');
    let end;
    while ((end = pending.indexOf(10)) !== -1) {
      const line = pending.subarray(0, end);
      pending = pending.subarray(end + 1);
      yield validateCommand(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)));
    }
  }
  if (pending.length) throw new Error('incomplete_frame');
}
