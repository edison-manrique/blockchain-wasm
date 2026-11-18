const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const tempDir = path.join(os.tmpdir(), 'blockchain-wasm-deploy-' + Date.now());
fs.mkdirSync(tempDir, { recursive: true });

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const item of fs.readdirSync(src)) {
    if (item === '__pycache__' || item.endsWith('.pyc')) continue;
    const s = path.join(src, item);
    const d = path.join(dest, item);
    if (fs.statSync(s).isDirectory()) {
      copyDir(s, d);
    } else {
      fs.copyFileSync(s, d);
    }
  }
}

const pubDir = path.resolve(__dirname, 'playground', 'dist');
console.log('Copying files from', pubDir, 'to', tempDir);
copyDir(pubDir, tempDir);
fs.writeFileSync(path.join(tempDir, '.nojekyll'), '');

const opts = { cwd: tempDir, stdio: 'inherit' };
execSync('git init', opts);
execSync('git config user.name "Edison Manrique"', opts);
execSync('git config user.email "edisonmanrique@users.noreply.github.com"', opts);
execSync('git remote add origin git@github.com:edison-manrique/blockchain-wasm.git', opts);
execSync('git checkout -b gh-pages', opts);
execSync('git add -A', opts);
execSync('git commit -m "deploy: playground for blockchain-wasm v4.0.0"', opts);
console.log('Pushing to origin gh-pages...');
execSync('git push -f origin gh-pages', opts);

fs.rmSync(tempDir, { recursive: true, force: true });
console.log('Deployed successfully to gh-pages!');
