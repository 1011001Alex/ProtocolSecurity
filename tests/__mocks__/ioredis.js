/**
 * =============================================================================
 * REDIS MOCK для ioredis
 * =============================================================================
 * Полноценная эмуляция Redis клиента для тестов без реального Redis сервера.
 * Поддерживает: SET/GET/DEL/EXPIRE/TTL, SET операции (SADD/SMEMBERS/SREM),
 * SCAN, PING, FLUSHDB, события (connect, error, close).
 * =============================================================================
 */

class MockRedisClient {
  constructor(options) {
    this.store = new Map();
    this.sets = new Map();
    this.status = 'ready';
    this._handlers = {};
    this._closed = false;

    // Эмитим событие connect асинхронно
    setTimeout(() => this.emit('connect'), 0);
    setTimeout(() => this.emit('ready'), 0);
  }

  // =========================================================================
  // STRING OPERATIONS
  // =========================================================================

  async set(key, value, ...args) {
    let ttl = null;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === 'EX' && args[i + 1]) {
        ttl = parseInt(args[i + 1]) * 1000;
      } else if (args[i] === 'PX' && args[i + 1]) {
        ttl = parseInt(args[i + 1]);
      } else if (args[i] === 'KEEPTTL') {
        // Сохраняем существующий TTL
        const existing = this.store.get(key);
        if (existing) {
          ttl = existing.ttl;
        }
      }
    }
    this.store.set(key, { value: String(value), ttl, createdAt: Date.now() });
    return 'OK';
  }

  async setex(key, ttl, value) {
    // SETEX = SET с TTL в секундах
    this.store.set(key, {
      value: String(value),
      ttl: ttl * 1000,
      createdAt: Date.now(),
    });
    return 'OK';
  }

  async psetex(key, ttlMs, value) {
    // PSETEX = SET с TTL в миллисекундах
    this.store.set(key, {
      value: String(value),
      ttl: ttlMs,
      createdAt: Date.now(),
    });
    return 'OK';
  }

  async get(key) {
    const item = this.store.get(key);
    if (!item) return null;
    // Проверяем TTL
    if (item.ttl && Date.now() - item.createdAt > item.ttl) {
      this.store.delete(key);
      return null;
    }
    return item.value;
  }

  async del(...keys) {
    let count = 0;
    for (const key of keys.flat()) {
      if (this.store.delete(key)) {
        count++;
      }
    }
    return count;
  }

  async exists(key) {
    const val = await this.get(key);
    return val !== null ? 1 : 0;
  }

  async expire(key, seconds) {
    const item = this.store.get(key);
    if (!item) return 0;
    item.ttl = seconds * 1000;
    item.createdAt = Date.now();
    return 1;
  }

  async pexpire(key, ms) {
    const item = this.store.get(key);
    if (!item) return 0;
    item.ttl = ms;
    item.createdAt = Date.now();
    return 1;
  }

  async ttl(key) {
    const item = this.store.get(key);
    if (!item) return -2;
    // Проверяем не истек ли TTL
    if (item.ttl && Date.now() - item.createdAt > item.ttl) {
      this.store.delete(key);
      return -2;
    }
    if (!item.ttl) return -1;
    const remaining = item.ttl - (Date.now() - item.createdAt);
    return remaining > 0 ? Math.floor(remaining / 1000) : -2;
  }

  async pttl(key) {
    const item = this.store.get(key);
    if (!item) return -2;
    if (item.ttl && Date.now() - item.createdAt > item.ttl) {
      this.store.delete(key);
      return -2;
    }
    if (!item.ttl) return -1;
    const remaining = item.ttl - (Date.now() - item.createdAt);
    return remaining > 0 ? Math.floor(remaining) : -2;
  }

  // =========================================================================
  // SET OPERATIONS
  // =========================================================================

  async sadd(key, ...members) {
    if (!this.sets.has(key)) {
      this.sets.set(key, new Set());
    }
    const set = this.sets.get(key);
    let added = 0;
    for (const member of members.flat()) {
      if (!set.has(member)) {
        set.add(member);
        added++;
      }
    }
    // Также сохраняем в store для get/smembers
    this.store.set(key, { value: Array.from(set).join(','), ttl: null, createdAt: Date.now() });
    return added;
  }

  async smembers(key) {
    const set = this.sets.get(key);
    if (!set) return [];
    return Array.from(set);
  }

  async srem(key, ...members) {
    const set = this.sets.get(key);
    if (!set) return 0;
    let removed = 0;
    for (const member of members.flat()) {
      if (set.delete(member)) {
        removed++;
      }
    }
    this.store.set(key, { value: Array.from(set).join(','), ttl: null, createdAt: Date.now() });
    return removed;
  }

  async scard(key) {
    const set = this.sets.get(key);
    if (!set) return 0;
    return set.size;
  }

  async sismember(key, member) {
    const set = this.sets.get(key);
    if (!set) return 0;
    return set.has(member) ? 1 : 0;
  }

  // =========================================================================
  // SCAN OPERATIONS
  // =========================================================================

  scanStream(options = {}) {
    const pattern = options.match || '*';
    const allKeys = Array.from(this.store.keys());
    const filteredKeys = allKeys.filter((key) => {
      if (pattern === '*') return true;
      // Простая glob pattern поддержка
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(key);
    });

    const asyncIterable = {
      [Symbol.asyncIterator]: async function* () {
        // Возвращаем ключи батчами
        const batchSize = options.highWaterMark || 100;
        for (let i = 0; i < filteredKeys.length; i += batchSize) {
          yield filteredKeys.slice(i, i + batchSize);
        }
      },
    };
    return asyncIterable;
  }

  async scan(cursor, options = {}) {
    const count = options.count || 10;
    const pattern = options.match || '*';
    const allKeys = Array.from(this.store.keys());
    const startIdx = parseInt(cursor) || 0;
    const filteredKeys = allKeys.filter((key) => {
      if (pattern === '*') return true;
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(key);
    });
    const endIdx = Math.min(startIdx + count, filteredKeys.length);
    const resultKeys = filteredKeys.slice(startIdx, endIdx);
    const nextCursor = endIdx >= filteredKeys.length ? '0' : String(endIdx);
    return [nextCursor, resultKeys];
  }

  // =========================================================================
  // CONNECTION & UTILITY OPERATIONS
  // =========================================================================

  async ping() {
    return 'PONG';
  }

  async flushdb() {
    this.store.clear();
    this.sets.clear();
    return 'OK';
  }

  async flushall() {
    this.store.clear();
    this.sets.clear();
    return 'OK';
  }

  async quit() {
    this._closed = true;
    this.status = 'close';
    this.emit('close');
    return 'OK';
  }

  async disconnect() {
    this._closed = true;
    this.status = 'close';
    this.emit('close');
  }

  // =========================================================================
  // EVENT EMULATION
  // =========================================================================

  on(event, handler) {
    if (!this._handlers[event]) {
      this._handlers[event] = [];
    }
    this._handlers[event].push(handler);
  }

  off(event, handler) {
    if (!this._handlers[event]) return;
    if (handler) {
      this._handlers[event] = this._handlers[event].filter((h) => h !== handler);
    } else {
      delete this._handlers[event];
    }
  }

  once(event, handler) {
    const onceHandler = (...args) => {
      handler(...args);
      this.off(event, onceHandler);
    };
    this.on(event, onceHandler);
  }

  emit(event, ...args) {
    const handlers = this._handlers[event];
    if (handlers) {
      handlers.forEach((handler) => handler(...args));
    }
  }

  // =========================================================================
  // PIPELINE & MULTI
  // =========================================================================

  pipeline() {
    const commands = [];
    const pipeline = {
      set: (key, value, ...args) => {
        commands.push({ cmd: 'set', args: [key, value, ...args] });
        return pipeline;
      },
      get: (key) => {
        commands.push({ cmd: 'get', args: [key] });
        return pipeline;
      },
      del: (...keys) => {
        commands.push({ cmd: 'del', args: keys });
        return pipeline;
      },
      expire: (key, seconds) => {
        commands.push({ cmd: 'expire', args: [key, seconds] });
        return pipeline;
      },
      sadd: (key, ...members) => {
        commands.push({ cmd: 'sadd', args: [key, ...members] });
        return pipeline;
      },
      smembers: (key) => {
        commands.push({ cmd: 'smembers', args: [key] });
        return pipeline;
      },
      exec: async () => {
        const results = [];
        for (const { cmd, args } of commands) {
          try {
            const result = await this[cmd](...args);
            results.push([null, result]);
          } catch (err) {
            results.push([err, null]);
          }
        }
        return results;
      },
    };
    return pipeline;
  }

  multi() {
    return this.pipeline();
  }

  // =========================================================================
  // DUPLICATE METHOD (для поддержки разных версий ioredis API)
  // =========================================================================

  duplicate() {
    return new MockRedisClient();
  }
}

// =========================================================================
// MODULE EXPORT
// =========================================================================

// Поддержка как default так и named export
module.exports = MockRedisClient;
module.exports.default = MockRedisClient;
