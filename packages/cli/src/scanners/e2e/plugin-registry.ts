/**
 * Plugin Registry
 *
 * Manages the registration and discovery of assertion plugins.
 */

import type { AssertionPlugin, PluginType } from './plugin-interface.js';
import { logger } from '../../utils/logger.js';

class PluginRegistry {
  private plugins: Map<string, AssertionPlugin> = new Map();

  /**
   * Register a plugin.
   */
  register(plugin: AssertionPlugin): void {
    if (this.plugins.has(plugin.name)) {
      logger.warn(`Plugin '${plugin.name}' is already registered, overwriting`);
    }
    this.plugins.set(plugin.name, plugin);
    logger.debug(`Registered plugin: ${plugin.name} (${plugin.type})`);
  }

  /**
   * Get a plugin by name.
   */
  get(name: string): AssertionPlugin | undefined {
    return this.plugins.get(name);
  }

  /**
   * Get all registered plugins.
   */
  getAll(): AssertionPlugin[] {
    return Array.from(this.plugins.values());
  }

  /**
   * Get plugins filtered by type.
   */
  getByType(type: PluginType): AssertionPlugin[] {
    return this.getAll().filter((p) => p.type === type);
  }

  /**
   * Get plugins filtered by name list.
   * If the filter is empty, returns all plugins.
   */
  getFiltered(names: string[]): AssertionPlugin[] {
    if (names.length === 0) return this.getAll();
    return names
      .map((name) => this.plugins.get(name))
      .filter((p): p is AssertionPlugin => p !== undefined);
  }

  /**
   * Clear all registered plugins.
   */
  clear(): void {
    this.plugins.clear();
  }
}

/** Singleton plugin registry */
export const pluginRegistry = new PluginRegistry();

/**
 * Load and register all built-in security assertion plugins.
 */
export async function loadBuiltinPlugins(): Promise<void> {
  try {
    const { AuthBypassPlugin } = await import('./plugins/auth-bypass.js');
    pluginRegistry.register(new AuthBypassPlugin());
  } catch (err) {
    logger.debug(`Failed to load auth-bypass plugin: ${err}`);
  }

  try {
    const { IdorPlugin } = await import('./plugins/idor.js');
    pluginRegistry.register(new IdorPlugin());
  } catch (err) {
    logger.debug(`Failed to load idor plugin: ${err}`);
  }

  try {
    const { SessionCookieFlagsPlugin } = await import('./plugins/session-cookie-flags.js');
    pluginRegistry.register(new SessionCookieFlagsPlugin());
  } catch (err) {
    logger.debug(`Failed to load session-cookie-flags plugin: ${err}`);
  }

  try {
    const { LogoutInvalidationPlugin } = await import('./plugins/logout-invalidation.js');
    pluginRegistry.register(new LogoutInvalidationPlugin());
  } catch (err) {
    logger.debug(`Failed to load logout-invalidation plugin: ${err}`);
  }

  try {
    const { LoginRateLimitPlugin } = await import('./plugins/login-rate-limit.js');
    pluginRegistry.register(new LoginRateLimitPlugin());
  } catch (err) {
    logger.debug(`Failed to load login-rate-limit plugin: ${err}`);
  }

  logger.debug(`Loaded ${pluginRegistry.getAll().length} assertion plugins`);
}
