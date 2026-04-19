import { Tracerney } from './dist/index.js';

const benignPrompts = [
  "What's the weather like today?",
  "Can you help me write a professional email?",
  "How do I write a SQL SELECT statement with JOIN?",
  "Explain the concept of machine learning",
  "What are the best practices for code review?",
  "How do I create a REST API?",
  "Tell me about the history of computers",
  "What are the benefits of regular exercise?",
  "How do I cook a healthy breakfast?",
  "Explain quantum computing to a beginner",
  "What programming languages should I learn?",
  "How do I write unit tests?",
  "What is the capital of France?",
  "Explain photosynthesis",
  "How do I troubleshoot my Wi-Fi?",
  "What are some good productivity tips?",
  "Explain the water cycle",
  "How do I learn to play guitar?",
  "What are the benefits of meditation?",
  "How do I start a small business?",
  "Explain relativity in simple terms",
  "What are the best time management techniques?",
  "How do I improve my public speaking?",
  "What is blockchain technology?",
  "How do I debug Python code?",
  "Explain the periodic table of elements",
  "What are the benefits of a healthy diet?",
  "How do I create a website?",
  "What is cloud computing?",
  "Explain the immune system",
  "How do I manage stress effectively?",
  "What are the best investment strategies?",
  "How do I learn a new language?",
  "Explain photosynthesis in detail",
  "What are the benefits of regular sleep?",
  "How do I optimize database queries?",
  "What is artificial intelligence?",
  "Explain the circulatory system",
  "How do I write clean code?",
  "What are the best career development practices?",
  "Explain evolution and natural selection",
  "How do I improve my writing skills?",
  "What is cybersecurity?",
  "Explain the nervous system",
  "How do I plan a vacation?",
  "What are the benefits of exercise?",
  "How do I improve my memory?",
  "Explain global warming",
  "What is machine learning?",
  "How do I choose a career path?"
];

async function testFalsePositives() {
  console.log('=== False Positive Test ===\n');

  const free = new Tracerney({ tier: 'free' });
  const pro = new Tracerney({ tier: 'pro' });

  // Wait for patterns to load
  await new Promise(r => setTimeout(r, 800));

  console.log(`Testing ${benignPrompts.length} legitimate prompts...\n`);

  let freeFalsePositives = 0;
  let proFalsePositives = 0;
  const proFPExamples = [];

  for (let i = 0; i < benignPrompts.length; i++) {
    const prompt = benignPrompts[i];

    try {
      await free.scanPrompt(prompt);
    } catch (e) {
      freeFalsePositives++;
      console.log(`Free FP: "${prompt}"`);
    }

    try {
      await pro.scanPrompt(prompt);
    } catch (e) {
      proFalsePositives++;
      proFPExamples.push(prompt);
      console.log(`Pro FP: "${prompt}"`);
    }
  }

  const freeRate = (freeFalsePositives / benignPrompts.length) * 100;
  const proRate = (proFalsePositives / benignPrompts.length) * 100;

  console.log('\n=== Results ===');
  console.log(`Free tier false positives: ${freeFalsePositives}/${benignPrompts.length} (${freeRate.toFixed(1)}%)`);
  console.log(`Pro tier false positives: ${proFalsePositives}/${benignPrompts.length} (${proRate.toFixed(1)}%)`);

  console.log('\nTarget: <5% false positive rate');
  if (proRate < 5) {
    console.log(`Result: ✅ PASS (${proRate.toFixed(1)}% FP rate)`);
  } else if (proRate < 10) {
    console.log(`Result: ⚠️ WARNING (${proRate.toFixed(1)}% FP rate - acceptable)`);
  } else {
    console.log(`Result: ❌ FAIL (${proRate.toFixed(1)}% FP rate - too high)`);
  }
}

testFalsePositives().catch(e => console.error('Test error:', e.message));
