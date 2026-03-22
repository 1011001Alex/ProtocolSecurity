/**
 * ============================================================================
 * CRYPTO MODULE INDEX
 * ============================================================================
 * Единая точка входа для всех криптографических модулей
 * ============================================================================
 */

// Основные сервисы
export {
  CryptoService,
  getCryptoService,
  initializeCryptoService,
  encrypt as encryptData,
  decrypt as decryptData,
} from './CryptoService';

export { SecureRandom, getSecureRandom, randomBytes, randomUUID, generateToken } from './SecureRandom';

export {
  HashService,
  StreamingHash,
  hash as hashData,
  hmac as hmacData,
} from './HashService';

export {
  KeyDerivationService,
  deriveKey,
  generateSalt,
} from './KeyDerivation';

export {
  DigitalSignatureService,
  generateSigningKeyPair,
  sign as signData,
  verify as verifySignature,
} from './DigitalSignature';

export {
  EnvelopeEncryptionService,
  encryptEnvelope,
  decryptEnvelope,
} from './EnvelopeEncryption';

export { KeyManager, generateKey } from './KeyManager';

export {
  PostQuantumCrypto,
  generatePQCKeyPair,
  pqcEncapsulate,
} from './PostQuantum';

// HSM/KMS провайдеры
export {
  HSMProvider,
  HSMProviderFactory,
  MultiKMSProvider,
  AWSKMSProvider,
  GCPKMSProvider,
  AzureKeyVaultProvider,
  LocalKMSProvider,
} from './HSMInterface';

// Типы
export type {
  // Базовые типы
  SecureBuffer,
  CryptoResult,
  CryptoErrorCode,
  
  // Симметричное шифрование
  SymmetricAlgorithm,
  SymmetricEncryptParams,
  SymmetricEncryptResult,
  SymmetricDecryptResult,
  
  // Асимметричное шифрование
  AsymmetricAlgorithm,
  AsymmetricKeyPair,
  AsymmetricEncryptResult,
  
  // Цифровые подписи
  SignatureAlgorithm,
  SigningKeyPair,
  SignatureResult,
  SignatureVerificationResult,
  
  // KDF
  KDFAlgorithm,
  KDFParams,
  Argon2Params,
  PBKDF2Params,
  HKDFParams,
  ScryptParams,
  
  // Хэширование
  HashAlgorithm,
  HashResult,
  
  // Конвертное шифрование
  EncryptionEnvelope,
  EnvelopeEncryptionParams,
  
  // Управление ключами
  KeyStatus,
  KeyType,
  KeyMetadata,
  KeyUsagePolicy,
  KeyOperation,
  KeyGenerationResult,
  KeyGenerationParams,
  
  // HSM/KMS
  KMSProviderType,
  KMSProviderConfig,
  KMSConnectionStatus,
  
  // Постквантовая криптография
  PQCAlgorithm,
  PQCPrimitiveType,
  PQCKeyPair,
  KEMEncapsulationResult,
  KEMDecapsulationResult,
  
  // Безопасность
  SecureMemoryConfig,
  MemoryStats,
  
  // Аудит
  LogLevel,
  AuditEventType,
  AuditEvent,
  LoggingConfig,
  
  // Конфигурация
  CryptoServiceConfig,
  DEFAULT_CRYPTO_CONFIG,
} from '../types/crypto.types';
