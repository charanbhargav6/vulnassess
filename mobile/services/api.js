/**
 * VulnAssess — Mobile API entry point
 * PATH: vulnassess-app/services/api.js
 *
 * Initialises apiCore with a secure auth storage adapter.
 */
import { createApi } from './apiCore';
import { authStorage } from './secureStorage';

const mobileStorage = {
  get:    async (key)        => authStorage.get(key),
  set:    async (key, value) => authStorage.set(key, value),
  remove: async (key)        => authStorage.remove(key),
  clear:  async ()           => authStorage.clear(),
};

export const api = createApi(mobileStorage);