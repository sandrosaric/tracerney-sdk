import { Tracerney } from './dist/index.js';

async function testPatternCount() {
  console.log('=== Pattern Count Verification ===\n');

  const free = new Tracerney({ tier: 'free' });
  const pro = new Tracerney({ tier: 'pro' });

  // Initial check
  console.log('Initial patterns (before async loading):');
  console.log(`Free tier: ${free.getStatus().patternMatcher.stats.totalPatterns}`);
  console.log(`Pro tier: ${pro.getStatus().patternMatcher.stats.totalPatterns}`);

  // Wait for async loading
  await new Promise(r => setTimeout(r, 800));

  console.log('\nAfter async loading (800ms):');
  const freeStats = free.getStatus().patternMatcher.stats;
  const proStats = pro.getStatus().patternMatcher.stats;

  console.log(`Free tier patterns: ${freeStats.totalPatterns}`);
  console.log(`Pro tier patterns: ${proStats.totalPatterns}`);

  const difference = proStats.totalPatterns - freeStats.totalPatterns;
  console.log(`\nDifference: ${difference} patterns`);
  console.log(`Expected: 675 Garak patterns`);
  console.log(`Result: ${difference === 675 ? '✅ EXACT MATCH' : difference > 670 ? '✅ PASS' : '❌ FAIL'}`);

  console.log('\n--- Free Tier Breakdown ---');
  console.log(`Critical: ${freeStats.bySeverity.critical}`);
  console.log(`High: ${freeStats.bySeverity.high}`);
  console.log(`Medium: ${freeStats.bySeverity.medium}`);
  console.log(`Low: ${freeStats.bySeverity.low}`);
  console.log(`Total: ${freeStats.totalPatterns}`);

  console.log('\n--- Pro Tier Breakdown ---');
  console.log(`Critical: ${proStats.bySeverity.critical}`);
  console.log(`High: ${proStats.bySeverity.high}`);
  console.log(`Medium: ${proStats.bySeverity.medium}`);
  console.log(`Low: ${proStats.bySeverity.low}`);
  console.log(`Total: ${proStats.totalPatterns}`);

  console.log('\n--- Category Distribution ---');
  console.log('Free tier categories:');
  Object.entries(freeStats.byCategory).forEach(([cat, count]) => {
    console.log(`  ${cat}: ${count}`);
  });
}

testPatternCount().catch(e => console.error('Test error:', e.message));
