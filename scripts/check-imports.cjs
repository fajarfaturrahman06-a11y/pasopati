const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', 'src');
const files = [];

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\.(ts|tsx)$/.test(entry.name)) files.push(full);
  }
}
walk(root);

const missing = [];
const re = /from\s+['"](\.[^'"]+)['"]/g;

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  let m;
  while ((m = re.exec(src))) {
    const spec = m[1];
    const base = path.resolve(path.dirname(file), spec);
    const candidates = [base, base + '.ts', base + '.tsx', base + '.js', base + '.jsx',
      path.join(base, 'index.ts'), path.join(base, 'index.tsx')];
    if (!candidates.some(c => fs.existsSync(c))) {
      missing.push(`${path.relative(root, file)} -> ${spec}`);
    }
  }
}

if (missing.length === 0) {
  console.log('SEMUA IMPORT RELATIF TERPENUHI (' + files.length + ' file dicek)');
} else {
  console.log('MISSING IMPORT:');
  [...new Set(missing)].forEach(x => console.log('  ' + x));
}
