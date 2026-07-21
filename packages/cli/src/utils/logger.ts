/**
 * Logger
 *
 * Structured console logger with colored output and log levels.
 */

import chalk from 'chalk';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

const LOG_LEVEL_LABELS: Record<LogLevel, string> = {
  [LogLevel.DEBUG]: chalk.gray('DEBUG'),
  [LogLevel.INFO]: chalk.blue('INFO '),
  [LogLevel.WARN]: chalk.yellow('WARN '),
  [LogLevel.ERROR]: chalk.red('ERROR'),
  [LogLevel.SILENT]: '',
};

class Logger {
  private level: LogLevel = LogLevel.INFO;

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  private log(level: LogLevel, message: string, ...args: unknown[]): void {
    if (level < this.level) return;

    const prefix = LOG_LEVEL_LABELS[level];
    const timestamp = chalk.gray(new Date().toISOString().slice(11, 23));
    console.log(`${timestamp} ${prefix} ${message}`, ...args);
  }

  debug(message: string, ...args: unknown[]): void {
    this.log(LogLevel.DEBUG, message, ...args);
  }

  info(message: string, ...args: unknown[]): void {
    this.log(LogLevel.INFO, message, ...args);
  }

  warn(message: string, ...args: unknown[]): void {
    this.log(LogLevel.WARN, message, ...args);
  }

  error(message: string, ...args: unknown[]): void {
    this.log(LogLevel.ERROR, message, ...args);
  }

  /** Print a blank line */
  blank(): void {
    if (this.level < LogLevel.SILENT) {
      console.log();
    }
  }

  /** Print a section header */
  section(title: string): void {
    if (this.level < LogLevel.SILENT) {
      console.log();
      console.log(chalk.bold.cyan(`━━━ ${title} ━━━`));
      console.log();
    }
  }

  /** Print a success message */
  success(message: string): void {
    if (this.level < LogLevel.SILENT) {
      console.log(`${chalk.green('✔')} ${message}`);
    }
  }

  /** Print a failure message */
  fail(message: string): void {
    if (this.level < LogLevel.SILENT) {
      console.log(`${chalk.red('✖')} ${message}`);
    }
  }
}

/** Singleton logger instance */
export const logger = new Logger();
