import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(__dirname, 'dist');

function fixImportsInFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf-8');

  // Fix imports: add .js extension or /index.js as needed
  content = content.replace(
    /from ['"](\.[^'"]+)['"];/g,
    (match, importPath) => {
      // Don't modify .json files or files that already have .js
      if (importPath.endsWith('.json') || importPath.endsWith('.js')) {
        return match;
      }

      // Check if it's a directory import (no file extension)
      const fullPath = path.join(path.dirname(filePath), importPath);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          // It's a directory, add /index.js
          return `from '${importPath}/index.js';`;
        }
      } catch (e) {
        // File doesn't exist or error, just add .js
      }

      // It's a file, add .js
      return `from '${importPath}.js';`;
    }
  );

  fs.writeFileSync(filePath, content);
}

function walkDir(dir) {
  const files = fs.readdirSync(dir);
  
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      walkDir(filePath);
    } else if (file.endsWith('.js')) {
      fixImportsInFile(filePath);
    }
  }
}

walkDir(distDir);
console.log('✅ Fixed ESM imports');
