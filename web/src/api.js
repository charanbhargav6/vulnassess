/**
 * VulnAssess — Web API entry point
 * PATH: vulnassess-web/src/api.js
 *
 * Initialises apiCore with an in-memory adapter.
 *
 * Web auth relies on HttpOnly cookies, so token persistence in localStorage
 * is intentionally avoided.
 */
import { createApi } from './apiCore';

const memoryStore = new Map();

const webStorage = {
  get:    async (key)        => memoryStore.get(key) ?? null,
  set:    async (key, value) => { memoryStore.set(key, value); },
  remove: async (key)        => { memoryStore.delete(key); },
  clear:  async ()           => { memoryStore.clear(); },
};

export const api = createApi(webStorage);