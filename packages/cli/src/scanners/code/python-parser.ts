import Parser from 'tree-sitter';
import Python from 'tree-sitter-python';
import { readFileSync } from 'node:fs';
import type { CodeCustomRule } from './rules.js';
import type { CodeFinding } from './ast-parser.js';

export function parseAndScanPython(filePath: string, customRules: CodeCustomRule[] = []): CodeFinding[] {
  const parser = new Parser();
  parser.setLanguage(Python);

  const sourceText = readFileSync(filePath, 'utf-8');
  const tree = parser.parse(sourceText);

  const findings: CodeFinding[] = [];
  const variableDeclarations = new Map<string, Parser.SyntaxNode>();

  function walk(node: Parser.SyntaxNode) {
    if (node.type === 'assignment') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left && right && left.type === 'identifier') {
        variableDeclarations.set(left.text, right);
      }
    }

    // 1. Evaluate custom rules
    for (const rule of customRules) {
      try {
        if (rule.check(node, { Parser, Python }, {})) {
          findings.push({
            file: filePath,
            line: node.startPosition.row + 1,
            snippet: sourceText.substring(node.startIndex, node.endIndex).split('\n')[0],
            type: `Custom Rule: ${rule.id}`,
            severity: rule.severity,
            message: rule.message,
          });
        }
      } catch {
        // Ignore rule errors silently
      }
    }

    // 2. Evaluate built-in rules
    checkBuiltInRules(node, sourceText, filePath, findings, variableDeclarations);

    for (const child of node.children) {
      walk(child);
    }
  }

  walk(tree.rootNode);
  return findings;
}

function checkBuiltInRules(
  node: Parser.SyntaxNode, 
  sourceText: string, 
  filePath: string, 
  findings: CodeFinding[],
  variableDeclarations: Map<string, Parser.SyntaxNode>
) {
  const line = node.startPosition.row + 1;
  const getSnippet = () => sourceText.substring(node.startIndex, node.endIndex).split('\n')[0];

  // Command Injection, SQL Injection, Deserialization
  if (node.type === 'call') {
    const fnNode = node.childForFieldName('function');
    if (fnNode && fnNode.text) {
      const fnName = fnNode.text;

      // 1. Command Injection: os.system(...)
      if (fnName === 'os.system') {
        findings.push({
          file: filePath,
          line,
          snippet: getSnippet(),
          type: 'Command Injection',
          severity: 'critical',
          message: 'Avoid os.system(). Use subprocess.run() without shell=True instead.',
        });
      } 
      // Command Injection: subprocess.run(..., shell=True)
      else if (fnName.includes('subprocess')) {
        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
          for (const arg of argsNode.namedChildren) {
            if (arg.type === 'keyword_argument') {
              const argName = arg.childForFieldName('name');
              const argValue = arg.childForFieldName('value');
              if (argName?.text === 'shell' && argValue?.text === 'True') {
                findings.push({
                  file: filePath,
                  line,
                  snippet: getSnippet(),
                  type: 'Command Injection',
                  severity: 'critical',
                  message: 'subprocess call with shell=True detected. This can lead to command injection.',
                });
              }
            }
          }
        }
      }
      
      // 2. Insecure Deserialization (Pickle)
      if (fnName === 'pickle.loads' || fnName === 'pickle.load') {
        findings.push({
          file: filePath,
          line,
          snippet: getSnippet(),
          type: 'Insecure Deserialization',
          severity: 'critical',
          message: 'Usage of pickle for deserialization is insecure. Use json or defusedxml instead.',
        });
      }

      // 3. Insecure Deserialization (YAML)
      if (fnName === 'yaml.load') {
        let isSafe = false;
        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
          for (const arg of argsNode.namedChildren) {
             if (arg.type === 'keyword_argument') {
                const name = arg.childForFieldName('name');
                const val = arg.childForFieldName('value');
                if (name?.text === 'Loader' && (val?.text === 'SafeLoader' || val?.text === 'yaml.SafeLoader')) {
                  isSafe = true;
                }
             } else if (arg.text === 'SafeLoader' || arg.text === 'yaml.SafeLoader') {
                isSafe = true; // positional
             }
          }
        }
        if (!isSafe) {
          findings.push({
            file: filePath,
            line,
            snippet: getSnippet(),
            type: 'Insecure Deserialization',
            severity: 'high',
            message: 'yaml.load() without SafeLoader is insecure. Use yaml.safe_load() or specify Loader=yaml.SafeLoader.',
          });
        }
      }
      
      // 4. SQL Injection (f-strings or concatenation in execute)
      if (fnName === 'execute' || fnName.endsWith('.execute')) {
        const argsNode = node.childForFieldName('arguments');
        if (argsNode && argsNode.namedChildren.length > 0) {
          const firstArg = argsNode.namedChildren[0];
          
          let isDynamic = false;

          const checkNodeIsDynamic = (n: Parser.SyntaxNode): boolean => {
            if (n.type === 'string' && n.text.startsWith('f')) {
              for (const child of n.children) {
                if (child.type === 'interpolation') return true;
              }
            }
            if (n.type === 'binary_operator') {
              const op = n.childForFieldName('operator');
              if (op?.text === '+') return true;
              // Python % formatting
              if (op?.text === '%') return true;
            }
            if (n.type === 'call') {
              const fn = n.childForFieldName('function');
              if (fn?.type === 'attribute' && fn.childForFieldName('attribute')?.text === 'format') {
                return true;
              }
            }
            return false;
          };

          if (checkNodeIsDynamic(firstArg)) {
            isDynamic = true;
          } else if (firstArg.type === 'identifier') {
            const initializer = variableDeclarations.get(firstArg.text);
            if (initializer && checkNodeIsDynamic(initializer)) {
              isDynamic = true;
            }
          }

          if (isDynamic) {
            findings.push({
              file: filePath,
              line,
              snippet: getSnippet(),
              type: 'SQL Injection',
              severity: 'high',
              message: 'Dynamic string concatenation or f-string in SQL execute() detected. Use parameterized queries instead.',
            });
          }
        }
      }

      // 5. debug=True in app.run
      if (fnName === 'app.run' || fnName.endsWith('.run')) {
        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
          for (const arg of argsNode.namedChildren) {
            if (arg.type === 'keyword_argument') {
              const name = arg.childForFieldName('name');
              const val = arg.childForFieldName('value');
              if (name?.text === 'debug' && val?.text === 'True') {
                findings.push({
                  file: filePath,
                  line,
                  snippet: getSnippet(),
                  type: 'Debug Enabled',
                  severity: 'medium',
                  message: 'Flask app running with debug=True. Disable debug mode in production to prevent code execution via the debugger.',
                });
              }
            }
          }
        }
      }
    }
  }

  // 6. Hardcoded Secrets (Assignments)
  if (node.type === 'assignment') {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (left && right && left.type === 'identifier' && right.type === 'string') {
      const varName = left.text.toLowerCase();
      if (/password|passwd|secret|api_key|apikey|token/.test(varName)) {
        // Check if string is a literal with length >= 8
        // right.text includes quotes
        const content = right.text.replace(/^['"]|['"]$/g, '');
        if (content.length >= 8 && !content.includes(' ') && !content.startsWith('env')) {
          findings.push({
            file: filePath,
            line,
            snippet: getSnippet(),
            type: 'Hardcoded Secret',
            severity: 'high',
            message: 'Possible hardcoded secret detected in Python source. Use environment variables or a secrets manager.',
          });
        }
      }
    }
  }
}
