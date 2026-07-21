/**
 * Shannon Entropy Calculator
 *
 * Detects high-entropy strings that may be secrets/tokens/keys.
 * High entropy (> 4.5 for 20+ char strings) suggests randomness
 * typical of generated credentials.
 */

/**
 * Calculate Shannon entropy of a string.
 *
 * Entropy measures the randomness/information content of a string.
 * - English text: ~3.5-4.0 bits/char
 * - Base64 random: ~5.5-6.0 bits/char
 * - Hex random: ~4.0 bits/char
 * - Max possible (uniform distribution over 256 chars): 8.0 bits/char
 *
 * @param str - The string to analyze
 * @returns Shannon entropy in bits per character
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Extract high-entropy tokens from a line of text.
 *
 * Splits the line into tokens and returns those exceeding
 * the entropy threshold and minimum length.
 *
 * @param line - Line of text to analyze
 * @param threshold - Minimum entropy to flag (default: 4.5)
 * @param minLength - Minimum token length to consider (default: 20)
 * @returns Array of high-entropy tokens found
 */
export function findHighEntropyStrings(
  line: string,
  threshold: number = 4.5,
  minLength: number = 20,
): Array<{ token: string; entropy: number }> {
  const results: Array<{ token: string; entropy: number }> = [];

  // Extract potential secret tokens — continuous strings of alphanumeric + common secret chars
  const tokenRegex = /[A-Za-z0-9+/=_\-]{20,}/g;
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(line)) !== null) {
    const token = match[0];
    if (token.length < minLength) continue;

    const entropy = calculateEntropy(token);
    if (entropy >= threshold) {
      results.push({ token, entropy });
    }
  }

  return results;
}
