import fs from 'fs';
import { Tracerney } from './dist/index.js';

// Load actual Garak samples from the bundle
const bundleData = JSON.parse(fs.readFileSync('pro.bundle.json', 'utf8'));
const garakSamples = bundleData.patterns.slice(0, 10).map(p => p.text);

async function testGarakSamples() {
  console.log('=== Garak Pattern Detection Test ===\n');

  const free = new Tracerney({ tier: 'free' });
  const pro = new Tracerney({ tier: 'pro' });

  // Wait for patterns to load
  await new Promise(r => setTimeout(r, 800));

  console.log(`Testing ${garakSamples.length} real Garak attack patterns...\n`);

  let freeBlocked = 0;
  let proBlocked = 0;

  for (let i = 0; i < garakSamples.length; i++) {
    const prompt = garakSamples[i];
    const displayText = prompt.substring(0, 70) + (prompt.length > 70 ? '...' : '');

    let freeDetected = false;
    let proDetected = false;

    try {
      await free.scanPrompt(prompt);
    } catch (e) {
      freeBlocked++;
      freeDetected = true;
    }

    try {
      await pro.scanPrompt(prompt);
    } catch (e) {
      proBlocked++;
      proDetected = true;
    }

    const freeStatus = freeDetected ? '✗ BLOCKED' : '✓ ALLOWED';
    const proStatus = proDetected ? '✗ BLOCKED' : '✓ ALLOWED';
    const improvement = !freeDetected && proDetected ? ' ← NEW DETECTION' : '';

    console.log(`${i + 1}. Free: ${freeStatus} | Pro: ${proStatus}${improvement}`);
    console.log(`   "${displayText}"\n`);
  }

  console.log('=== Results ===');
  console.log(`Free tier blocked: ${freeBlocked}/${garakSamples.length} Garak attacks`);
  console.log(`Pro tier blocked: ${proBlocked}/${garakSamples.length} Garak attacks`);
  console.log(`\nNew detections in Pro: ${proBlocked - freeBlocked} additional attacks caught`);

  if (proBlocked >= garakSamples.length * 0.7) {
    console.log('Result: ✅ PASS (Pro tier catching most Garak patterns)');
  } else if (proBlocked > freeBlocked) {
    console.log('Result: ⚠️ PARTIAL (Pro tier catches some additional patterns)');
  } else {
    console.log('Result: ❌ FAIL (Pro tier not detecting additional patterns)');
  }
}

testGarakSamples().catch(e => console.error('Test error:', e.message));
