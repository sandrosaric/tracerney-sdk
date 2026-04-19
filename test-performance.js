import { Tracerney } from './dist/index.js';

async function testPerformance() {
  console.log('=== Performance Test ===\n');

  const sdk = new Tracerney({ tier: 'pro' });

  // Wait for patterns to load
  await new Promise(r => setTimeout(r, 800));

  const testPrompts = [
    "How do I write a SQL SELECT statement?",
    "Can you help me with Python?",
    "What's the weather today?",
    "Explain machine learning",
    "Write a professional email"
  ];

  console.log('Warming up...');
  for (const prompt of testPrompts) {
    try {
      await sdk.scanPrompt(prompt);
    } catch (e) {
      // Expected for some prompts
    }
  }

  console.log('\nMeasuring detection latency (1000 iterations)...');
  const iterations = 1000;
  const testPrompt = "How do I write a SQL SELECT statement?";

  const start = Date.now();
  for (let i = 0; i < iterations; i++) {
    try {
      await sdk.scanPrompt(testPrompt);
    } catch (e) {
      // Ignore
    }
  }
  const elapsed = Date.now() - start;
  const avgTime = elapsed / iterations;

  console.log(`Total time: ${elapsed}ms`);
  console.log(`Average per scan: ${avgTime.toFixed(2)}ms`);
  console.log(`Target: <5ms`);
  console.log(`Result: ${avgTime < 5 ? '✅ PASS' : '⚠️ WARNING'} (${avgTime.toFixed(2)}ms)`);

  // Also test sync detection capability
  console.log('\nPattern stats:');
  const stats = sdk.getStatus().patternMatcher.stats;
  console.log(`Total patterns: ${stats.totalPatterns}`);
  console.log(`Critical: ${stats.bySeverity.critical}`);
  console.log(`High: ${stats.bySeverity.high}`);
  console.log(`Medium: ${stats.bySeverity.medium}`);
  console.log(`Low: ${stats.bySeverity.low}`);
}

testPerformance().catch(e => console.error('Test error:', e.message));
