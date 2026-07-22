import ts from 'typescript';
import { readFileSync } from 'node:fs';

import type { CodeCustomRule } from './rules.js';

export interface CodeFinding {
  file: string;
  line: number;
  snippet: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  message: string;
}

export function parseAndScanFile(filePath: string, customRules: CodeCustomRule[] = []): CodeFinding[] {
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
