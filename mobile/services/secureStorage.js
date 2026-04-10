import AsyncStorage from '@react-native-async-storage/async-storage';
import * as SecureStore from 'expo-secure-store';

const AUTH_KEYS = ['token', 'role', 'email', 'scan_count', 'scan_limit'];
const AUTH_KEY_SET = new Set(AUTH_KEYS);

let secureStoreAvailablePromise;

const isSecureStoreAvailable = async () => {
  if (!secureStoreAvailablePromise) {
    secureStoreAvailablePromise = SecureStore.isAvailableAsync().catch(() => false);
  }
  return secureStoreAvailablePromise;
};

const readSecure = async (key) => {
  try {
    if (await isSecureStoreAvailable()) {
      const value = await SecureStore.getItemAsync(key);
      if (value != null) return value;
    }
  } catch (_) {}
  return AsyncStorage.getItem(key);
};

const writeSecure = async (key, value) => {
  if (value == null) {
    await removeSecure(key);
    return;
  }

  let stored = false;
  try {
    if (await isSecureStoreAvailable()) {
      await SecureStore.setItemAsync(key, String(value));
      stored = true;
    }
  } catch (_) {
    // AsyncStorage fallback below
  }

  if (!stored) {
    await AsyncStorage.setItem(key, String(value));
    return;
  }

  // Remove stale legacy values from AsyncStorage for auth keys.
  await AsyncStorage.removeItem(key);
};

const removeSecure = async (key) => {
  try {
    if (await isSecureStoreAvailable()) {
      await SecureStore.deleteItemAsync(key);
    }
  } catch (_) {}
  await AsyncStorage.removeItem(key);
};

export const authStorage = {
  get: async (key) => {
    if (AUTH_KEY_SET.has(key)) return readSecure(key);
    return AsyncStorage.getItem(key);
  },

  set: async (key, value) => {
    if (AUTH_KEY_SET.has(key)) {
      await writeSecure(key, value);
      return;
    }
    await AsyncStorage.setItem(key, String(value));
  },

  remove: async (key) => {
    if (AUTH_KEY_SET.has(key)) {
      await removeSecure(key);
      return;
    }
    await AsyncStorage.removeItem(key);
  },

  clear: async () => {
    await Promise.all(AUTH_KEYS.map((key) => removeSecure(key)));
  },
};
