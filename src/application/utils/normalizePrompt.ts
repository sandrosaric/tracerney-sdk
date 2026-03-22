/**
 * Normalize prompt text for consistent pattern matching
 *
 * Steps:
 * 1. Lowercase
 * 2. Unicode NFKC normalization (collapses homoglyphs: ｐ→p, ＡＢＣ→ABC)
 * 3. Strip non-alphanumeric except basic punctuation
 * 4. Collapse multiple whitespace → single space
 * 5. Trim
 *
 * This prevents attackers from using Unicode tricks or weird spacing to bypass regex.
 */

export function normalizePrompt(input: string): string {
  if (!input || typeof input !== 'string') {
    return '';
  }

  let normalized = input
    // Step 1: Lowercase
    .toLowerCase()
    // Step 2: Unicode normalization (NFKC collapses fullwidth, superscripts, ligatures, etc.)
    .normalize('NFKC')
    // Step 3: Keep only alphanumeric + basic punctuation (. , ! ? ' " - _ ( ) [ ])
    .replace(/[^\w\s.,'!?"_\-()[\]]/g, '')
    // Step 4: Collapse multiple spaces/newlines/tabs into single space
    .replace(/\s+/g, ' ')
    // Step 5: Trim
    .trim();

  return normalized;
}

/**
 * Batch normalize multiple prompts
 */
export function normalizePrompts(inputs: string[]): string[] {
  return inputs.map(normalizePrompt);
}
