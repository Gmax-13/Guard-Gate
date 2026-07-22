import ts from 'typescript';
import { readFileSync } from 'node:fs';

import type { SastCustomRule } from './rules.js';

export interface SastFinding {
  file: string;
  line: number;
  snippet: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
}

export function parseAndScanFile(filePath: string, customRules: SastCustomRule[] = []): SastFinding[] {
  const findings: SastFinding[] = [];
  const sourceText = readFileSync(filePath, 'utf-8');
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    true
  );

  function getLineInfo(node: ts.Node) {
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    return { line: line + 1, snippet: node.getText() };
  }

  function walk(node: ts.Node) {
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
      if (
        (ts.isIdentifier(expr) && expr.text === 'exec') ||
        (ts.isPropertyAccessExpression(expr) && expr.name.text === 'exec')
      ) {
        // If the argument is not a simple string literal, it's highly dangerous
        const arg = node.arguments[0];
        if (arg && !ts.isStringLiteral(arg) && !ts.isNoSubstitutionTemplateLiteral(arg)) {
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
        // If it's a template string with expressions (interpolation) or string concatenation (+)
        if (
          (arg && ts.isTemplateExpression(arg)) ||
          (arg && ts.isBinaryExpression(arg) && arg.operatorToken.kind === ts.SyntaxKind.PlusToken)
        ) {
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

    // Execute custom rules
    for (const rule of customRules as SastCustomRule[]) {
      // If nodeType is specified, ensure it matches
      if (rule.nodeType) {
        let nodeMatches = false;
        if (rule.nodeType === 'CallExpression' && ts.isCallExpression(node)) nodeMatches = true;
        else if (rule.nodeType === 'PropertyAccessExpression' && ts.isPropertyAccessExpression(node)) nodeMatches = true;
        else if (rule.nodeType === 'JsxAttribute' && ts.isJsxAttribute(node)) nodeMatches = true;
        
        if (!nodeMatches) continue;
      }

      // Test regex pattern against the node's source code
      const regex = new RegExp(rule.pattern as string);
      if (regex.test(node.getText())) {
        const { line, snippet } = getLineInfo(node);
        findings.push({
          file: filePath,
          line,
          snippet,
          type: rule.id as string,
          severity: rule.severity as 'low' | 'medium' | 'high' | 'critical',
          message: rule.message as string
        });
      }
    }

    ts.forEachChild(node, walk);
  }

  walk(sourceFile);
  return findings;
}
