#!/usr/bin/env node
const { spawnSync } = require('child_process');
const { mkdtempSync, writeFileSync } = require('fs');
const { tmpdir } = require('os');
const { join } = require('path');
const https = require('https');

const INSTALLER_URL = "https://raw.githubusercontent.com/sbomit/sbomit/main/install.sh";

function download(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302)
        return download(res.headers.location).then(resolve).catch(reject);
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve(data));
      res.on('error', reject);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version') || args.includes('-v')) {
    console.log('sbomit-init 0.1.0'); process.exit(0);
  }
  console.log('==> Downloading sbomit-init...');
  const script = await download(INSTALLER_URL);
  const tmp = join(mkdtempSync(join(tmpdir(), 'sbomit-')), 'install.sh');
  writeFileSync(tmp, script, { mode: 0o755 });
  const r = spawnSync('bash', [tmp, ...args], { stdio: 'inherit', env: process.env });
  process.exit(r.status || 0);
}

main().catch((e) => { console.error('Error:', e.message); process.exit(1); });
