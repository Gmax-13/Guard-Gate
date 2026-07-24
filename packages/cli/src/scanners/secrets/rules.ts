/**
 * Secret Detection Rules
 *
 * Curated set of regex patterns for detecting common secrets and credentials.
 * Modeled after well-known open-source rule sets but independently implemented.
 */

import { Severity } from '../../types/report.js';

export interface SecretRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of what this rule detects */
  description: string;
  /** Regex pattern for detection */
  regex: RegExp;
  /** Severity if matched */
  severity: Severity;
  /** Keywords that might appear near the secret (used for context hinting) */
  keywords?: string[];
}

/**
 * Built-in secret detection rules.
 * Each regex is designed to minimize false positives while catching real secrets.
 */
export const BUILT_IN_RULES: SecretRule[] = [
  // ─── AWS ────────────────────────────────────────────────────────────
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    description: 'Detects AWS Access Key IDs (starts with AKIA)',
    regex: /(?:^|[^A-Za-z0-9/+])(?:AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)/g,
    severity: Severity.CRITICAL,
    keywords: ['aws', 'access_key', 'AWS_ACCESS_KEY_ID'],
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    description: 'Detects AWS Secret Access Keys (40-char base64)',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})(?:['"]|$|\s)/gi,
    severity: Severity.CRITICAL,
    keywords: ['aws', 'secret_key', 'AWS_SECRET_ACCESS_KEY'],
  },

  // ─── GitHub ─────────────────────────────────────────────────────────
  {
    id: 'github-personal-access-token',
    name: 'GitHub Personal Access Token',
    description: 'Detects GitHub PATs (ghp_, gho_, ghu_, ghs_, ghr_ prefixed)',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/g,
    severity: Severity.CRITICAL,
    keywords: ['github', 'token', 'GITHUB_TOKEN'],
  },
  {
    id: 'github-fine-grained-token',
    name: 'GitHub Fine-Grained Token',
    description: 'Detects GitHub fine-grained personal access tokens',
    regex: /github_pat_[A-Za-z0-9_]{22,255}/g,
    severity: Severity.CRITICAL,
    keywords: ['github', 'token'],
  },

  // ─── Google ─────────────────────────────────────────────────────────
  {
    id: 'google-api-key',
    name: 'Google API Key',
    description: 'Detects Google API keys (AIza prefix)',
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    severity: Severity.HIGH,
    keywords: ['google', 'api_key', 'GOOGLE_API_KEY'],
  },
  {
    id: 'google-oauth-client-secret',
    name: 'Google OAuth Client Secret',
    description: 'Detects Google OAuth client secrets',
    regex: /(?:client_secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{24})['"]?/gi,
    severity: Severity.HIGH,
    keywords: ['google', 'oauth', 'client_secret'],
  },

  // ─── Stripe ─────────────────────────────────────────────────────────
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    description: 'Detects Stripe secret API keys (sk_live_ or sk_test_ prefix)',
    regex: /sk_(?:live|test)_[A-Za-z0-9]{20,100}/g,
    severity: Severity.CRITICAL,
    keywords: ['stripe', 'secret_key', 'STRIPE_SECRET_KEY'],
  },
  {
    id: 'stripe-publishable-key',
    name: 'Stripe Publishable Key',
    description: 'Detects Stripe publishable keys (pk_live_ or pk_test_ prefix)',
    regex: /pk_(?:live|test)_[A-Za-z0-9]{20,100}/g,
    severity: Severity.LOW,
    keywords: ['stripe', 'publishable_key'],
  },

  // ─── Slack ──────────────────────────────────────────────────────────
  {
    id: 'slack-bot-token',
    name: 'Slack Bot Token',
    description: 'Detects Slack Bot User OAuth tokens',
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/g,
    severity: Severity.HIGH,
    keywords: ['slack', 'bot', 'token', 'SLACK_BOT_TOKEN'],
  },
  {
    id: 'slack-webhook-url',
    name: 'Slack Webhook URL',
    description: 'Detects Slack incoming webhook URLs',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]{8,12}\/B[A-Za-z0-9]{8,12}\/[A-Za-z0-9]{24}/g,
    severity: Severity.HIGH,
    keywords: ['slack', 'webhook'],
  },

  // ─── Private Keys ──────────────────────────────────────────────────
  {
    id: 'rsa-private-key',
    name: 'RSA Private Key',
    description: 'Detects RSA private key headers',
    regex: /-----BEGIN RSA PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    keywords: ['rsa', 'private_key'],
  },
  {
    id: 'ssh-private-key',
    name: 'SSH Private Key',
    description: 'Detects SSH/OpenSSH private key headers',
    regex: /-----BEGIN (?:OPENSSH|DSA|EC|PGP) PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    keywords: ['ssh', 'private_key'],
  },

  // ─── Database Connection Strings ────────────────────────────────────
  {
    id: 'database-url',
    name: 'Database Connection String',
    description: 'Detects database connection strings with credentials',
    regex: /(?:mongodb|postgres|postgresql|mysql|mssql|redis):\/\/[^:]+:[^@]+@[^/\s]+/gi,
    severity: Severity.CRITICAL,
    keywords: ['database_url', 'DATABASE_URL', 'connection_string'],
  },

  // ─── JWT ────────────────────────────────────────────────────────────
  {
    id: 'jwt-token',
    name: 'JWT Token',
    description: 'Detects JSON Web Tokens',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: Severity.MEDIUM,
    keywords: ['jwt', 'token', 'authorization', 'bearer'],
  },

  // ─── Generic ────────────────────────────────────────────────────────
  {
    id: 'generic-api-key',
    name: 'Generic API Key',
    description: 'Detects generic API key assignments',
    regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]([A-Za-z0-9_\-/+=]{20,64})['"]/gi,
    severity: Severity.HIGH,
    keywords: ['api_key', 'apikey', 'api_secret'],
  },
  {
    id: 'generic-password',
    name: 'Hardcoded Password',
    description: 'Detects hardcoded password assignments',
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,64})['"]/gi,
    severity: Severity.HIGH,
    keywords: ['password', 'passwd', 'pwd'],
  },
  {
    id: 'generic-secret',
    name: 'Generic Secret',
    description: 'Detects generic secret assignments',
    regex: /(?:secret|token|credential)\s*[=:]\s*['"]([A-Za-z0-9_\-/+=]{16,64})['"]/gi,
    severity: Severity.HIGH,
    keywords: ['secret', 'token', 'credential'],
  },

  // ─── Twilio ─────────────────────────────────────────────────────────
  {
    id: 'twilio-api-key',
    name: 'Twilio API Key',
    description: 'Detects Twilio API keys (SK prefix)',
    regex: /SK[0-9a-fA-F]{32}/g,
    severity: Severity.HIGH,
    keywords: ['twilio', 'TWILIO_API_KEY'],
  },

  // ─── SendGrid ───────────────────────────────────────────────────────
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    description: 'Detects SendGrid API keys (SG. prefix)',
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    severity: Severity.HIGH,
    keywords: ['sendgrid', 'SENDGRID_API_KEY'],
  },

  // ─── Heroku ─────────────────────────────────────────────────────────
  {
    id: 'heroku-api-key',
    name: 'Heroku API Key',
    description: 'Detects Heroku API keys',
    regex: /(?:heroku[_-]?api[_-]?key)\s*[=:]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?/gi,
    severity: Severity.HIGH,
    keywords: ['heroku', 'HEROKU_API_KEY'],
  },

  // ─── npm ────────────────────────────────────────────────────────────
  {
    id: 'npm-token',
    name: 'npm Access Token',
    description: 'Detects npm access tokens',
    regex: /(?:\/\/registry\.npmjs\.org\/:_authToken=)([A-Za-z0-9_-]{36,})/g,
    severity: Severity.CRITICAL,
    keywords: ['npm', 'npmrc', '_authToken'],
  },
];
