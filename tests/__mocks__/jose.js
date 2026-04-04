/**
 * Mock для jose library (JWT cryptography)
 * Используется в тестах чтобы избежать ESM issues с Jest
 */

const crypto = require('crypto');

// Mock реализации основных функций jose
function importSPKI(spki, alg, options) {
  return Promise.resolve({
    type: 'public',
    format: 'pem',
    data: spki
  });
}

function importPKCS8(pkcs8, alg, options) {
  return Promise.resolve({
    type: 'private', 
    format: 'pem',
    data: pkcs8
  });
}

function importJWK(jwk, options) {
  return Promise.resolve(jwk);
}

function exportJWK(key) {
  return Promise.resolve(key);
}

function SignJWT(payload) {
  this.payload = payload;
  this.protectedHeader = {};
  
  this.setProtectedHeader = function(header) {
    this.protectedHeader = header;
    return this;
  };
  
  this.sign = async function(key) {
    const header = Buffer.from(JSON.stringify(this.protectedHeader)).toString('base64url');
    const payload = Buffer.from(JSON.stringify(this.payload)).toString('base64url');
    const signature = crypto.randomBytes(64).toString('base64url');
    return `${header}.${payload}.${signature}`;
  };
}

function jwtVerify(token, key, options) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT token');
  }
  
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  return Promise.resolve({
    payload,
    protectedHeader: JSON.parse(Buffer.from(parts[0], 'base64url').toString())
  });
}

function CompactSign(payload) {
  this.payload = payload;
  return this;
}

CompactSign.prototype.setProtectedHeader = function(header) {
  this.protectedHeader = header;
  return this;
};

CompactSign.prototype.sign = async function(key) {
  const header = Buffer.from(JSON.stringify(this.protectedHeader)).toString('base64url');
  const payload = Buffer.from(JSON.stringify(this.payload)).toString('base64url');
  const signature = crypto.randomBytes(64).toString('base64url');
  return `${header}.${payload}.${signature}`;
};

function compactVerify(token, key, options) {
  return jwtVerify(token, key, options);
}

function generateKeyPair(alg, options) {
  return new Promise((resolve, reject) => {
    try {
      let keyPair;
      if (alg === 'RS256' || alg === 'RS384' || alg === 'RS512') {
        keyPair = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
      } else if (alg === 'ES256' || alg === 'ES384' || alg === 'ES512') {
        const curve = alg === 'ES256' ? 'P-256' : alg === 'ES384' ? 'P-384' : 'P-521';
        keyPair = crypto.generateKeyPairSync('ec', {
          namedCurve: curve,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
      } else if (alg === 'EdDSA') {
        keyPair = crypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
      } else {
        keyPair = crypto.generateKeyPairSync('ec', {
          namedCurve: 'P-256',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
      }
      
      resolve({
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
      });
    } catch (error) {
      reject(error);
    }
  });
}

function createRemoteJWKSet(url, options) {
  return async function(token) {
    return jwtVerify(token, {});
  };
}

// Экспорт всех функций
module.exports = {
  importSPKI,
  importPKCS8,
  importJWK,
  exportJWK,
  SignJWT,
  jwtVerify,
  CompactSign,
  compactVerify,
  generateKeyPair,
  createRemoteJWKSet
};
