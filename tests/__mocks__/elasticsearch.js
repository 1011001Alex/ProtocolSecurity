/**
 * =============================================================================
 * ELASTICSEARCH MOCK для @elastic/elasticsearch Client
 * =============================================================================
 * Полноценная эмуляция Elasticsearch клиента для тестов без реального ES кластера.
 * Поддерживает: index, search, get, delete, createIndex, deleteIndex, bulk,
 * update, count, ping, close.
 * =============================================================================
 */

class MockElasticsearchClient {
  constructor(config) {
    this.config = config || {};
    this.indices = new Map();
    this.documents = new Map();
    this._closed = false;
    this._connected = true;
  }

  // =========================================================================
  // CONNECTION
  // =========================================================================

  async ping() {
    return { body: { status: 'green', name: 'mock-es', cluster_name: 'mock-cluster' } };
  }

  async close() {
    this._closed = true;
    this._connected = false;
    return {};
  }

  // =========================================================================
  // INDICES API
  // =========================================================================

  async create(params) {
    const index = params.index || (params.body && params.body.index);
    if (!index) {
      throw { statusCode: 400, message: 'Missing index parameter' };
    }
    this.indices.set(index, params.body || {});
    if (!this.documents.has(index)) {
      this.documents.set(index, new Map());
    }
    return { body: { acknowledged: true, shards_acknowledged: true, index } };
  }

  async delete(params) {
    const index = params.index;
    if (!this.indices.has(index)) {
      throw { statusCode: 404, message: `index_not_found_exception`, meta: { body: { error: { index } } } };
    }
    this.indices.delete(index);
    this.documents.delete(index);
    return { body: { acknowledged: true } };
  }

  async exists(params) {
    const index = params.index;
    return { body: this.indices.has(index), statusCode: this.indices.has(index) ? 200 : 404 };
  }

  // =========================================================================
  // DOCUMENT API
  // =========================================================================

  async index(params) {
    const { index, id, body, document } = params;
    // Поддержка新旧 API: body (v7) или document (v8)
    const doc = body || document;
    if (!index) {
      throw { statusCode: 400, message: 'Missing index parameter' };
    }
    if (!this.documents.has(index)) {
      this.documents.set(index, new Map());
    }
    const docId = id || `doc-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const now = new Date().toISOString();
    const storedDoc = {
      ...doc,
      _index: index,
      _id: docId,
      '@timestamp': doc['@timestamp'] || now,
    };
    this.documents.get(index).set(docId, storedDoc);
    return {
      body: {
        _index: index,
        _id: docId,
        _version: 1,
        result: 'created',
        _shards: { total: 1, successful: 1, failed: 0 },
        _seq_no: 0,
        _primary_term: 1,
      },
    };
  }

  async get(params) {
    const { index, id } = params;
    if (!this.documents.has(index)) {
      throw { statusCode: 404, message: 'Not found', meta: { body: { found: false } } };
    }
    const docs = this.documents.get(index);
    if (!docs.has(id)) {
      throw { statusCode: 404, message: 'Not found', meta: { body: { found: false } } };
    }
    const source = docs.get(id);
    return {
      body: {
        _index: index,
        _id: id,
        _version: 1,
        _seq_no: 0,
        _primary_term: 1,
        found: true,
        _source: source,
      },
    };
  }

  async deleteDocument(params) {
    const { index, id } = params;
    if (!this.documents.has(index)) {
      throw { statusCode: 404, message: 'Not found' };
    }
    const docs = this.documents.get(index);
    if (!docs.has(id)) {
      throw { statusCode: 404, message: 'Not found' };
    }
    docs.delete(id);
    return { body: { _index: index, _id: id, result: 'deleted' } };
  }

  async update(params) {
    const { index, id, body, doc } = params;
    if (!this.documents.has(index)) {
      throw { statusCode: 404, message: 'Not found' };
    }
    const docs = this.documents.get(index);
    const existing = docs.get(id) || {};
    const updatedDoc = { ...existing, ...(body?.doc || doc || body) };
    docs.set(id, updatedDoc);
    return {
      body: {
        _index: index,
        _id: id,
        _version: 2,
        result: 'updated',
        _shards: { total: 1, successful: 1, failed: 0 },
      },
    };
  }

  // =========================================================================
  // SEARCH API
  // =========================================================================

  async search(params) {
    const { index, body } = params;
    const indices = Array.isArray(index) ? index : [index];
    const allHits = [];

    for (const idx of indices) {
      const docs = this.documents.get(idx);
      if (!docs) continue;

      for (const [id, source] of docs.entries()) {
        allHits.push({
          _index: idx,
          _id: id,
          _score: 1.0,
          _source: source,
        });
      }
    }

    // Простая фильтрация если есть query
    let filteredHits = allHits;
    if (body?.query) {
      filteredHits = this._applyQuery(allHits, body.query);
    }

    // Сортировка
    if (body?.sort) {
      filteredHits = this._applySort(filteredHits, body.sort);
    }

    // Pagination
    const from = body?.from || 0;
    const size = body?.size || 10;
    const paginatedHits = filteredHits.slice(from, from + size);

    return {
      body: {
        took: 1,
        timed_out: false,
        _shards: { total: 1, successful: 1, skipped: 0, failed: 0 },
        hits: {
          total: { value: filteredHits.length, relation: 'eq' },
          max_score: 1.0,
          hits: paginatedHits,
        },
      },
    };
  }

  async count(params) {
    const { index, body } = params;
    const indices = Array.isArray(index) ? index : [index];
    let totalCount = 0;

    for (const idx of indices) {
      const docs = this.documents.get(idx);
      if (!docs) continue;
      totalCount += docs.size;
    }

    return {
      body: {
        count: totalCount,
        _shards: { total: 1, successful: 1, skipped: 0, failed: 0 },
      },
    };
  }

  // =========================================================================
  // BULK API
  // =========================================================================

  async bulk(params) {
    const { body } = params;
    const items = [];
    let i = 0;

    while (i < body.length) {
      const action = body[i];
      const doc = body[i + 1];

      if (action.index) {
        const indexResult = await this.index({
          index: action.index._index || action.index,
          id: action.index._id,
          body: doc,
        });
        items.push({ index: indexResult.body });
      } else if (action.create) {
        const createResult = await this.index({
          index: action.create._index || action.create,
          id: action.create._id,
          body: doc,
        });
        items.push({ create: createResult.body });
      } else if (action.delete) {
        try {
          await this.deleteDocument({
            index: action.delete._index || action.delete,
            id: action.delete._id,
          });
          items.push({ delete: { result: 'deleted' } });
        } catch (err) {
          items.push({ delete: { result: 'not_found', status: 404 } });
        }
      }

      i += 2;
    }

    return {
      body: {
        took: 1,
        errors: false,
        items,
      },
    };
  }

  // =========================================================================
  // HELPER METHODS
  // =========================================================================

  _applyQuery(hits, query) {
    if (!query) return hits;

    // Простая поддержка match_all
    if (query.match_all) return hits;

    // Простая поддержка term/terms
    if (query.term) {
      const [field, value] = Object.entries(query.term)[0];
      return hits.filter((h) => h._source[field] === value);
    }

    if (query.terms) {
      const [field, values] = Object.entries(query.terms)[0];
      return hits.filter((h) => values.includes(h._source[field]));
    }

    // Простая поддержка match
    if (query.match) {
      const [field, value] = Object.entries(query.match)[0];
      return hits.filter((h) => {
        const fieldValue = h._source[field];
        if (typeof fieldValue === 'string' && typeof value === 'string') {
          return fieldValue.toLowerCase().includes(value.toLowerCase());
        }
        return fieldValue === value;
      });
    }

    // Bool query
    if (query.bool) {
      let result = hits;
      if (query.bool.must) {
        for (const subQuery of Array.isArray(query.bool.must) ? query.bool.must : [query.bool.must]) {
          result = this._applyQuery(result, subQuery);
        }
      }
      if (query.bool.must_not) {
        for (const subQuery of Array.isArray(query.bool.must_not) ? query.bool.must_not : [query.bool.must_not]) {
          const matched = this._applyQuery(result, subQuery);
          result = result.filter((h) => !matched.some((m) => m._id === h._id));
        }
      }
      if (query.bool.should) {
        const shouldHits = [];
        for (const subQuery of Array.isArray(query.bool.should) ? query.bool.should : [query.bool.should]) {
          shouldHits.push(...this._applyQuery(hits, subQuery));
        }
        const uniqueIds = new Set(shouldHits.map((h) => h._id));
        result = hits.filter((h) => uniqueIds.has(h._id));
      }
      if (query.bool.filter) {
        for (const subQuery of Array.isArray(query.bool.filter) ? query.bool.filter : [query.bool.filter]) {
          result = this._applyQuery(result, subQuery);
        }
      }
      return result;
    }

    // Range query
    if (query.range) {
      const [field, rangeParams] = Object.entries(query.range)[0];
      return hits.filter((h) => {
        const val = h._source[field];
        if (val === undefined) return false;
        if (rangeParams.gte !== undefined && val < rangeParams.gte) return false;
        if (rangeParams.gt !== undefined && val <= rangeParams.gt) return false;
        if (rangeParams.lte !== undefined && val > rangeParams.lte) return false;
        if (rangeParams.lt !== undefined && val >= rangeParams.lt) return false;
        return true;
      });
    }

    // По умолчанию возвращаем все
    return hits;
  }

  _applySort(hits, sort) {
    if (!sort || !Array.isArray(sort)) return hits;
    return [...hits].sort((a, b) => {
      for (const sortField of sort) {
        const field = typeof sortField === 'string' ? sortField : Object.keys(sortField)[0];
        const order = typeof sortField === 'string' ? 'asc' : sortField[field] || 'asc';
        const aVal = a._source[field];
        const bVal = b._source[field];
        if (aVal < bVal) return order === 'asc' ? -1 : 1;
        if (aVal > bVal) return order === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }

  // =========================================================================
  // EVENTS (для совместимости с event-based API)
  // =========================================================================

  on(event, handler) {
    // No-op для мока
  }

  off(event, handler) {
    // No-op для мока
  }

  emit(event, ...args) {
    // No-op для мока
  }
}

// =========================================================================
// EXPORT — поддержка разных стилей импорта
// =========================================================================

// Для `const { Client } = require('elasticsearch')`
module.exports.Client = MockElasticsearchClient;

// Для `const elasticsearch = require('elasticsearch')`
module.exports.default = MockElasticsearchClient;

// Для `require('@elastic/elasticsearch').Client`
module.exports.defaultClient = MockElasticsearchClient;
