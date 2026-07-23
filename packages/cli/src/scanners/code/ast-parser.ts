import ts from 'typescript';
import { readFileSync } from 'node:fs';
import { extname } from 'node:path';

import type { CodeCustomRule } from './rules.js';

export interface CodeFinding {
  file: string;
  line: number;
  snippet: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  message: string;
}

/** File extensions that should use the TypeScript AST parser */
const JS_TS_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.mts', '.cts']);

export function parseAndScanFile(filePath: string, customRules: CodeCustomRule[] = []): CodeFinding[] {
  const ext = extname(filePath).toLowerCase();

  // Route to the appropriate scanner based on file extension
  if (JS_TS_EXTENSIONS.has(ext)) {
    return parseAndScanJsTs(filePath, customRules);
  }

  if (ext === '.py') {
    return regexScanPython(filePath);
  }

  // Fallback: attempt JS/TS AST parse for unknown extensions (existing behavior)
  return parseAndScanJsTs(filePath, customRules);
}

// ─── JS/TS AST-based Scanner ────────────────────────────────────────────

function parseAndScanJsTs(filePath: string, customRules: CodeCustomRule[] = []): CodeFinding[] {
  const findings: CodeFinding[] = [];
  const sourceText = readFileSync(filePath, 'utf-8');
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    true
  );

  const variableDeclarations = new Map<string, ts.Node>();

  function getLineInfo(node: ts.Node) {
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    return { line: line + 1, snippet: node.getText() };
  }

  function walk(node: ts.Node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      variableDeclarations.set(node.name.text, node.initializer);
    }

    // Check for eval() calls
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      
      // Direct eval()
      if (ts.isIdentifier(expr) && expr.text === 'eval') {
        const { line, snippet } = getLineInfo(node);
        findings.push({
          file: filePath,
          line,
          snippet,
          type: 'Code Injection',
          severity: 'critical',
          message: 'Use of eval() detected. This can lead to arbitrary code execution.'
        });
      }

      // Check for exec(), child_process.exec(), etc.
      let isExecCall = false;

      if (ts.isIdentifier(expr) && expr.text === 'exec') {
        isExecCall = true;
      } else if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'exec') {
        // Naive heuristic to avoid flagging RegExp.exec()
        const obj = expr.expression;
        let objName = '';
        if (ts.isIdentifier(obj)) {
          objName = obj.text.toLowerCase();
        } else if (ts.isPropertyAccessExpression(obj)) {
          objName = obj.name.text.toLowerCase();
        }

        if (
          !ts.isRegularExpressionLiteral(obj) && 
          !objName.includes('regex') && 
          !objName.includes('pattern')
        ) {
          isExecCall = true;
        }
      }

      if (isExecCall) {
        // If the argument is not a simple string literal, it's highly dangerous
        const arg = node.arguments[0];
        let isDangerous = false;
        
        if (arg) {
          if (!ts.isStringLiteral(arg) && !ts.isNoSubstitutionTemplateLiteral(arg)) {
            isDangerous = true;
            // Taint tracking: if it's an identifier, check its initializer
            if (ts.isIdentifier(arg)) {
              const initializer = variableDeclarations.get(arg.text);
              if (initializer && (ts.isStringLiteral(initializer) || ts.isNoSubstitutionTemplateLiteral(initializer))) {
                isDangerous = false; // It was safely initialized with a static string
              }
            }
          }
        }

        if (isDangerous) {
          const { line, snippet } = getLineInfo(node);
          findings.push({
            file: filePath,
            line,
            snippet,
            type: 'Command Injection',
            severity: 'critical',
            message: 'Dynamic argument passed to exec(). This can lead to OS command injection.'
          });
        }
      }

      // Check for SQL query calls with dynamic concatenation: db.query(`SELECT * FROM users WHERE id = ${id}`)
      if (
        ts.isPropertyAccessExpression(expr) && 
        (expr.name.text === 'query' || expr.name.text === 'execute')
      ) {
        const arg = node.arguments[0];
        let isDynamic = false;
        
        if (arg) {
          if (ts.isTemplateExpression(arg)) isDynamic = true;
          else if (ts.isBinaryExpression(arg) && arg.operatorToken.kind === ts.SyntaxKind.PlusToken) isDynamic = true;
          else if (ts.isIdentifier(arg)) {
            const initializer = variableDeclarations.get(arg.text);
            if (initializer) {
              if (ts.isTemplateExpression(initializer)) isDynamic = true;
              else if (ts.isBinaryExpression(initializer) && initializer.operatorToken.kind === ts.SyntaxKind.PlusToken) isDynamic = true;
            }
          }
        }
        
        if (isDynamic) {
          const { line, snippet } = getLineInfo(node);
          findings.push({
            file: filePath,
            line,
            snippet,
            type: 'SQL Injection',
            severity: 'high',
            message: 'Dynamic SQL query detected. Use parameterized queries instead.'
          });
        }
      }

      // Check for crypto.createHash('md5')
      if (
        ts.isPropertyAccessExpression(expr) &&
        expr.name.text === 'createHash'
      ) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteral(arg) && arg.text.toLowerCase() === 'md5') {
          const { line, snippet } = getLineInfo(node);
          findings.push({
            file: filePath,
            line,
            snippet,
            type: 'Weak Cryptography',
            severity: 'medium',
            message: 'Use of MD5 hashing algorithm detected. MD5 is cryptographically weak.'
          });
        }
      }
    }

    // Check for dangerouslySetInnerHTML (React)
    if (ts.isJsxAttribute(node) && node.name.getText() === 'dangerouslySetInnerHTML') {
      const { line, snippet } = getLineInfo(node);
      findings.push({
        file: filePath,
        line,
        snippet,
        type: 'XSS Injection',
        severity: 'critical',
        message: 'Direct use of dangerouslySetInnerHTML detected. This can lead to XSS if input is unsanitized.'
      });
    }

    // Execute custom JS rules
    for (const rule of customRules) {
      try {
        if (rule.check(node, ts, {})) {
          const { line, snippet } = getLineInfo(node);
          findings.push({
            file: filePath,
            line,
            snippet,
            type: rule.id,
            severity: rule.severity,
            message: rule.message
          });
        }
      } catch (err) {
        // ignore errors in rule check to not crash the whole scan
      }
    }

    ts.forEachChild(node, walk);
  }

  walk(sourceFile);
  return findings;
}

// ─── Python Regex-based Scanner ─────────────────────────────────────────

/** Regex patterns for detecting critical security issues in Python code */
interface PythonPattern {
  /** Pattern to match against each line */
  regex: RegExp;
  /** Finding type */
  type: string;
  /** Severity */
  severity: CodeFinding['severity'];
  /** Message */
  message: string;
}

const PYTHON_PATTERNS: PythonPattern[] = [
  // Code injection
  {
    regex: /\beval\s*\(/,
    type: 'Code Injection',
    severity: 'critical',
    message: 'Use of eval() detected. This can lead to arbitrary code execution.',
  },
  {
    regex: /\bexec\s*\(/,
    type: 'Code Injection',
    severity: 'critical',
    message: 'Use of exec() detected. This can lead to arbitrary code execution.',
  },
  // Command injection
  {
    regex: /\bos\.system\s*\(/,
    type: 'Command Injection',
    severity: 'critical',
    message: 'Use of os.system() detected. This can lead to OS command injection. Use subprocess with a list argument instead.',
  },
  {
    regex: /\bos\.popen\s*\(/,
    type: 'Command Injection',
    severity: 'critical',
    message: 'Use of os.popen() detected. This can lead to OS command injection.',
  },
  {
    regex: /\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/,
    type: 'Command Injection',
    severity: 'critical',
    message: 'subprocess called with shell=True. This can lead to OS command injection if user input reaches the command string.',
  },
  // SQL injection — string concatenation
  {
    regex: /(?:execute|cursor\.execute|\.query)\s*\(\s*(?:f["']|["'].*\s*(?:\+|%|\.format))/,
    type: 'SQL Injection',
    severity: 'high',
    message: 'Dynamic SQL query detected. Use parameterized queries instead.',
  },
  // SQL injection — string concatenation with variable assignment
  {
    regex: /\bquery\s*=\s*(?:f["'](?:SELECT|INSERT|UPDATE|DELETE)|["'](?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|%|\.format))/i,
    type: 'SQL Injection',
    severity: 'high',
    message: 'SQL query built via string concatenation/formatting. Use parameterized queries instead.',
  },
  // Deserialization
  {
    regex: /\bpickle\.loads?\s*\(/,
    type: 'Insecure Deserialization',
    severity: 'high',
    message: 'Use of pickle.load(s) detected. Deserializing untrusted data with pickle can lead to arbitrary code execution.',
  },
  {
    regex: /\byaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    type: 'Insecure Deserialization',
    severity: 'high',
    message: 'Use of yaml.load() without SafeLoader detected. Use yaml.safe_load() or specify Loader=SafeLoader.',
  },
  // Weak cryptography
  {
    regex: /\bhashlib\.(?:md5|sha1)\s*\(/,
    type: 'Weak Cryptography',
    severity: 'medium',
    message: 'Use of weak hash algorithm (MD5/SHA1) detected. Use SHA-256 or stronger.',
  },
  // Hardcoded secrets (Python-specific patterns)
  {
    regex: /\b(?:password|passwd|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i,
    type: 'Hardcoded Secret',
    severity: 'high',
    message: 'Possible hardcoded secret detected in Python source. Use environment variables or a secrets manager.',
  },
  // Debug / dangerous defaults
  {
    regex: /\bapp\.run\s*\([^)]*debug\s*=\s*True/,
    type: 'Debug Enabled',
    severity: 'medium',
    message: 'Flask app running with debug=True. Disable debug mode in production to prevent code execution via the debugger.',
  },
];

function regexScanPython(filePath: string): CodeFinding[] {
  const findings: CodeFinding[] = [];
  const sourceText = readFileSync(filePath, 'utf-8');
  const lines = sourceText.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNumber = i + 1;

    // Skip comments
    if (trimmed.startsWith('#')) continue;

    for (const pattern of PYTHON_PATTERNS) {
      // Reset regex state
      pattern.regex.lastIndex = 0;

      if (pattern.regex.test(line)) {
        findings.push({
          file: filePath,
          line: lineNumber,
          snippet: trimmed,
          type: pattern.type,
          severity: pattern.severity,
          message: pattern.message,
        });
      }
    }
  }

  return findings;
}
