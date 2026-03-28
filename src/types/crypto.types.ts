/**
 * ============================================================================
 * КРИПТОГРАФИЧЕСКИЕ ТИПЫ И ИНТЕРФЕЙСЫ
 * ============================================================================
 * Полная типизация для всех криптографических операций
 * Включает типы для симметричного/асимметричного шифрования, подписей, KMS
 * ============================================================================
 */

// ============================================================================
// WEB CRYPTO API ТИПЫ (для совместимости)
// ============================================================================

/**
 * CryptoKey из Web Crypto API
 * Используем type alias для совместимости с Node.js crypto
 */
export type CryptoKey = import('crypto').KeyObject;

// ============================================================================
// БАЗОВЫЕ ТИПЫ ДАННЫХ
// ============================================================================

/**
 * Безопасный буфер с возможностью очистки памяти
 * Используется для хранения чувствительных данных (ключи, пароли)
 */
export interface SecureBuffer {
  /** Сырые данные */
  readonly data: Uint8Array;
  /** Метка времени создания */
  readonly createdAt: number;
  /** Время жизни в мс (0 = бессрочно) */
  readonly ttl: number;
  /** Флаг очистки памяти */
  readonly autoZero: boolean;
}

/**
 * Результат криптографической операции
 */
export interface CryptoResult<T> {
  /** Успешный результат */
  success: boolean;
  /** Данные результата */
  data?: T;
  /** Код ошибки */
  errorCode?: CryptoErrorCode;
  /** Сообщение об ошибке */
  errorMessage?: string;
  /** Дополнительный контекст */
  context?: Record<string, unknown>;
}

/**
 * Коды криптографических ошибок
 */
export enum CryptoErrorCode {
  // Общие ошибки
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
  INVALID_ARGUMENT = 'INVALID_ARGUMENT',
  BUFFER_TOO_SMALL = 'BUFFER_TOO_SMALL',
  OPERATION_TIMEOUT = 'OPERATION_TIMEOUT',

  // Ошибки шифрования
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  INVALID_CIPHERTEXT = 'INVALID_CIPHERTEXT',
  AUTH_TAG_MISMATCH = 'AUTH_TAG_MISMATCH',
  NONCE_REUSED = 'NONCE_REUSED',

  // Ошибки ключей
  KEY_GENERATION_FAILED = 'KEY_GENERATION_FAILED',
  KEY_DERIVATION_FAILED = 'KEY_DERIVATION_FAILED',
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  KEY_EXPIRED = 'KEY_EXPIRED',
  KEY_REVOKED = 'KEY_REVOKED',
  INVALID_KEY_FORMAT = 'INVALID_KEY_FORMAT',
  INVALID_KEY_SIZE = 'INVALID_KEY_SIZE',

  // Ошибки подписи
  SIGNATURE_GENERATION_FAILED = 'SIGNATURE_GENERATION_FAILED',
  SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  SIGNATURE_EXPIRED = 'SIGNATURE_EXPIRED',

  // Ошибки хэширования
  HASH_COMPUTATION_FAILED = 'HASH_COMPUTATION_FAILED',
  INVALID_HASH = 'INVALID_HASH',
  HASH_MISMATCH = 'HASH_MISMATCH',

  // Ошибки HSM/KMS
  HSM_NOT_AVAILABLE = 'HSM_NOT_AVAILABLE',
  HSM_COMMUNICATION_ERROR = 'HSM_COMMUNICATION_ERROR',
  KMS_SERVICE_ERROR = 'KMS_SERVICE_ERROR',
  KMS_ACCESS_DENIED = 'KMS_ACCESS_DENIED',

  // Ошибки постквантовой криптографии
  PQC_NOT_SUPPORTED = 'PQC_NOT_SUPPORTED',
  PQC_KEY_EXCHANGE_FAILED = 'PQC_KEY_EXCHANGE_FAILED',
  PQC_INVALID_PARAMETERS = 'PQC_INVALID_PARAMETERS',

  // Ошибки безопасности
  SIDE_CHANNEL_DETECTED = 'SIDE_CHANNEL_DETECTED',
  TIMING_ATTACK_DETECTED = 'TIMING_ATTACK_DETECTED',
  MEMORY_SECURITY_VIOLATION = 'MEMORY_SECURITY_VIOLATION',
  ENTROPY_INSUFFICIENT = 'ENTROPY_INSUFFICIENT',

  // Ошибки аутентификации (для совместимости)
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  TOKEN_INVALID = 'TOKEN_INVALID',
  INVALID_KEY = 'INVALID_KEY',

  // Дополнительные ошибки для совместимости
  ACCESS_DENIED = 'ACCESS_DENIED',
}

// ============================================================================
// ТИПЫ ДЛЯ СИММЕТРИЧНОГО ШИФРОВАНИЯ
// ============================================================================

/**
 * Алгоритмы симметричного шифрования
 */
export type SymmetricAlgorithm = 
  | 'AES-128-GCM'
  | 'AES-256-GCM'
  | 'AES-128-CTR'
  | 'AES-256-CTR'
  | 'AES-128-CBC'
  | 'AES-256-CBC'
  | 'ChaCha20-Poly1305'
  | 'XChaCha20-Poly1305';

/**
 * Параметры для симметричного шифрования
 */
export interface SymmetricEncryptParams {
  /** Алгоритм шифрования */
  algorithm: SymmetricAlgorithm;
  /** Ключ шифрования (raw bytes) */
  key: Uint8Array;
  /** Уникальный номер (nonce/IV) */
  nonce: Uint8Array;
  /** Дополнительные аутентифицированные данные */
  additionalData?: Uint8Array;
}

/**
 * Результат симметричного шифрования
 */
export interface SymmetricEncryptResult {
  /** Зашифрованные данные */
  ciphertext: Uint8Array;
  /** Тег аутентификации (для AEAD) */
  authTag?: Uint8Array;
  /** Использованный nonce */
  nonce: Uint8Array;
}

/**
 * Результат симметричного расшифрования
 */
export interface SymmetricDecryptResult {
  /** Расшифрованные данные */
  plaintext: Uint8Array;
  /** Статус проверки тега аутентификации */
  authValid: boolean;
}

// ============================================================================
// ТИПЫ ДЛЯ АСИММЕТРИЧНОГО ШИФРОВАНИЯ
// ============================================================================

/**
 * Алгоритмы асимметричного шифрования
 */
export type AsymmetricAlgorithm = 
  | 'RSA-OAEP-2048'
  | 'RSA-OAEP-3072'
  | 'RSA-OAEP-4096'
  | 'RSA-PKCS1-2048'
  | 'RSA-PKCS1-4096'
  | 'ECDH-P256'
  | 'ECDH-P384'
  | 'ECDH-P521'
  | 'X25519';

/**
 * Пара асимметричных ключей
 */
export interface AsymmetricKeyPair {
  /** Открытый ключ */
  publicKey: CryptoKey;
  /** Закрытый ключ */
  privateKey: CryptoKey;
  /** Идентификатор пары ключей */
  keyId: string;
  /** Алгоритм */
  algorithm: AsymmetricAlgorithm;
  /** Время создания */
  createdAt: Date;
  /** Время истечения срока действия */
  expiresAt?: Date;
}

/**
 * Результат асимметричного шифрования
 */
export interface AsymmetricEncryptResult {
  /** Зашифрованные данные */
  ciphertext: Uint8Array;
  /** Идентификатор ключа */
  keyId: string;
  /** Алгоритм */
  algorithm: string;
}

// ============================================================================
// ТИПЫ ДЛЯ ЦИФРОВЫХ ПОДПИСЕЙ
// ============================================================================

/**
 * Алгоритмы цифровых подписей
 */
export type SignatureAlgorithm = 
  | 'Ed25519'
  | 'Ed448'
  | 'ECDSA-P256-SHA256'
  | 'ECDSA-P384-SHA384'
  | 'ECDSA-P521-SHA512'
  | 'RSA-PSS-2048-SHA256'
  | 'RSA-PSS-3072-SHA384'
  | 'RSA-PSS-4096-SHA512'
  | 'RSA-PKCS1-2048-SHA256'
  | 'RSA-PKCS1-4096-SHA512';

/**
 * Пара ключей для подписи
 */
export interface SigningKeyPair {
  /** Открытый ключ для верификации */
  publicKey: CryptoKey;
  /** Закрытый ключ для подписи */
  privateKey: CryptoKey;
  /** Идентификатор пары ключей */
  keyId: string;
  /** Алгоритм подписи */
  algorithm: SignatureAlgorithm;
  /** Время создания */
  createdAt: Date;
  /** Время истечения срока действия */
  expiresAt?: Date;
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Результат создания подписи
 */
export interface SignatureResult {
  /** Подпись в байтах */
  signature: Uint8Array;
  /** Алгоритм подписи */
  algorithm: string;
  /** Идентификатор ключа */
  keyId: string;
  /** Хэш подписанных данных */
  dataHash: Uint8Array;
  /** Временная метка подписи */
  timestamp: number;
}

/**
 * Результат верификации подписи
 */
export interface SignatureVerificationResult {
  /** Подпись валидна */
  valid: boolean;
  /** Детали верификации */
  details: {
    /** Ключ действителен */
    keyValid: boolean;
    /** Подпись не искажена */
    signatureIntact: boolean;
    /** Срок действия не истек */
    notExpired: boolean;
    /** Ключ не отозван */
    notRevoked: boolean;
    /** Алгоритм (опционально) */
    algorithm?: string;
    /** Метод верификации (опционально) */
    verifiedWith?: string;
    /** Ошибка (опционально) */
    error?: string;
  };
  /** Время верификации */
  verifiedAt: Date;
}

// ============================================================================
// ТИПЫ ДЛЯ ДЕРИВАЦИИ КЛЮЧЕЙ (KDF)
// ============================================================================

/**
 * Алгоритмы деривации ключей
 */
export type KDFAlgorithm = 
  | 'Argon2id'
  | 'Argon2i'
  | 'Argon2d'
  | 'PBKDF2-SHA256'
  | 'PBKDF2-SHA512'
  | 'HKDF-SHA256'
  | 'HKDF-SHA512'
  | 'scrypt';

/**
 * Параметры для Argon2
 */
export interface Argon2Params {
  /** Объем памяти в КБ */
  memorySize: number;
  /** Количество итераций */
  iterations: number;
  /** Степень параллелизма */
  parallelism: number;
  /** Длина вывода в байтах */
  hashLength: number;
}

/**
 * Параметры для PBKDF2
 */
export interface PBKDF2Params {
  /** Алгоритм хэша */
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** Количество итераций */
  iterations: number;
  /** Длина вывода в байтах */
  keyLength: number;
}

/**
 * Параметры для HKDF
 */
export interface HKDFParams {
  /** Алгоритм хэша */
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** Соль */
  salt: Uint8Array;
  /** Контекстная информация */
  info: Uint8Array;
  /** Длина вывода в байтах */
  keyLength: number;
}

/**
 * Параметры для scrypt
 */
export interface ScryptParams {
  /** CPU/memory cost parameter */
  N: number;
  /** Block size */
  r: number;
  /** Parallelization parameter */
  p: number;
  /** Длина вывода в байтах */
  keyLength: number;
}

/**
 * Объединенные параметры KDF
 */
export interface KDFParams {
  /** Алгоритм */
  algorithm: KDFAlgorithm;
  /** Параметры Argon2 */
  argon2?: Argon2Params;
  /** Параметры PBKDF2 */
  pbkdf2?: PBKDF2Params;
  /** Параметры HKDF */
  hkdf?: HKDFParams;
  /** Параметры scrypt */
  scrypt?: ScryptParams;
}

// ============================================================================
// ТИПЫ ДЛЯ ХЭШИРОВАНИЯ
// ============================================================================

/**
 * Алгоритмы хэширования
 */
export type HashAlgorithm = 
  | 'SHA-1'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  | 'BLAKE2b'
  | 'BLAKE2s'
  | 'BLAKE3';

/**
 * Результат хэширования
 */
export interface HashResult {
  /** Хэш в байтах */
  hash: Uint8Array;
  /** Алгоритм */
  algorithm: string;
  /** Длина входа в байтах */
  inputLength: number;
  /** Длина выхода в байтах */
  outputLength: number;
}

// ============================================================================
// ТИПЫ ДЛЯ КОНВЕРТНОГО ШИФРОВАНИЯ (ENVELOPE ENCRYPTION)
// ============================================================================

/**
 * Конверт с зашифрованными данными
 */
export interface EncryptionEnvelope {
  /** Версия формата */
  version: number;
  /** Идентификатор конверта */
  envelopeId: string;
  /** Зашифрованный ключ данных (DEK) */
  encryptedDek: Uint8Array;
  /** Идентификатор ключа шифрования ключей (KEK) */
  kekId: string;
  /** Алгоритм шифрования KEK */
  kekAlgorithm: string;
  /** Алгоритм шифрования данных */
  dataAlgorithm: SymmetricAlgorithm;
  /** Nonce для шифрования данных */
  dataNonce: Uint8Array;
  /** Зашифрованные данные */
  ciphertext: Uint8Array;
  /** Тег аутентификации */
  authTag?: Uint8Array;
  /** Дополнительные аутентифицированные данные */
  additionalData?: Uint8Array;
  /** Метаданные */
  metadata?: Record<string, unknown>;
  /** Временная метка создания */
  createdAt: number;
  /** Временная метка истечения */
  expiresAt?: number;
}

/**
 * Параметры для создания конверта
 */
export interface EnvelopeEncryptionParams {
  /** Данные для шифрования */
  plaintext: Uint8Array;
  /** Алгоритм шифрования данных */
  dataAlgorithm: SymmetricAlgorithm;
  /** Идентификатор KEK */
  kekId: string;
  /** Дополнительные аутентифицированные данные */
  additionalData?: Uint8Array;
  /** Метаданные */
  metadata?: Record<string, unknown>;
  /** Срок жизни конверта (мс) */
  ttl?: number;
}

// ============================================================================
// ТИПЫ ДЛЯ УПРАВЛЕНИЯ КЛЮЧАМИ (KMS)
// ============================================================================

/**
 * Статус ключа
 */
export type KeyStatus = 
  | 'ACTIVE'           // Ключ активен и используется
  | 'PENDING_ACTIVATION'  // Ожидает активации
  | 'PENDING_DEACTIVATION' // Ожидает деактивации
  | 'DISABLED'         // Ключ отключен
  | 'DESTROYED'        // Ключ уничтожен
  | 'IMPORT_FAILED'   // Ошибка импорта
  | 'EXPIRED';        // Срок действия истек

/**
 * Тип ключа
 */
export type KeyType = 
  | 'SYMMETRIC'        // Симметричный ключ
  | 'ASYMMETRIC_SIGN'  // Пара ключей для подписи
  | 'ASYMMETRIC_ENC'   // Пара ключей для шифрования
  | 'MASTER_KEY'       // Мастер-ключ (KEK)
  | 'DATA_KEY'         // Ключ данных (DEK)
  | 'WRAPPING_KEY';    // Ключ обертывания

/**
 * Метаданные ключа
 */
export interface KeyMetadata {
  /** Уникальный идентификатор ключа */
  keyId: string;
  /** Имя ключа */
  name: string;
  /** Описание */
  description?: string;
  /** Тип ключа */
  keyType: KeyType;
  /** Алгоритм */
  algorithm: string;
  /** Длина ключа в битах */
  keySize: number;
  /** Статус ключа */
  status: KeyStatus;
  /** Время создания */
  createdAt: Date;
  /** Время активации */
  activatedAt?: Date;
  /** Время истечения срока действия */
  expiresAt?: Date;
  /** Время последнего использования */
  lastUsedAt?: Date;
  /** Версия ключа (для ротации) */
  version: number;
  /** Предыдущая версия */
  previousVersion?: number;
  /** Теги для классификации */
  tags?: Record<string, string>;
  /** Политика использования */
  usagePolicy?: KeyUsagePolicy;
  /** Владелец ключа */
  owner?: string;
}

/**
 * Политика использования ключа
 */
export interface KeyUsagePolicy {
  /** Разрешенные операции */
  allowedOperations: KeyOperation[];
  /** Запрещенные операции */
  deniedOperations: KeyOperation[];
  /** Ограничение по времени использования */
  timeRestrictions?: {
    /** Начало допустимого периода */
    validFrom: Date;
    /** Конец допустимого периода */
    validTo: Date;
  };
  /** Ограничение по количеству использований */
  usageLimit?: {
    /** Максимальное количество использований */
    maxUses: number;
    /** Текущее количество использований */
    currentUses: number;
  };
  /** Требуемый уровень аутентификации */
  requiredAuthLevel?: number;
  /** Разрешенные IP-адреса */
  allowedIpRanges?: string[];
}

/**
 * Операции с ключами
 */
export type KeyOperation = 
  | 'ENCRYPT'
  | 'DECRYPT'
  | 'SIGN'
  | 'VERIFY'
  | 'WRAP_KEY'
  | 'UNWRAP_KEY'
  | 'DERIVE_KEY'
  | 'GENERATE_MAC'
  | 'VERIFY_MAC';

/**
 * Результат генерации ключа
 */
export interface KeyGenerationResult {
  /** Метаданные ключа */
  metadata: KeyMetadata;
  /** Ключ (если экспортируемый) */
  keyMaterial?: Uint8Array;
  /** Идентификатор ключа */
  keyId: string;
}

/**
 * Параметры для генерации ключа
 */
export interface KeyGenerationParams {
  /** Тип ключа */
  keyType: KeyType;
  /** Алгоритм */
  algorithm: string;
  /** Длина ключа в битах */
  keySize: number;
  /** Имя ключа */
  name?: string;
  /** Описание */
  description?: string;
  /** Теги */
  tags?: Record<string, string>;
  /** Политика использования */
  usagePolicy?: KeyUsagePolicy;
  /** Срок жизни ключа (мс) */
  ttl?: number;
  /** Флаг экспортируемости */
  exportable: boolean;
}

// ============================================================================
// ТИПЫ ДЛЯ HSM/KMS
// ============================================================================

/**
 * Типы провайдеров HSM/KMS
 */
export type KMSProviderType =
  | 'AWS_KMS'
  | 'GCP_KMS'
  | 'AZURE_KEY_VAULT'
  | 'HASHICORP_VAULT'
  | 'PKCS11_HSM'
  | 'YUBIKEY_HSM'
  | 'LOCAL_SECURE_ENCLAVE'
  | 'CUSTOM';

// ============================================================================
// ТИПЫ ДЛЯ HSM INTERFACE
// ============================================================================

/**
 * Пара ключей HSM
 */
export interface HSMKeyPair {
  /** Идентификатор пары ключей */
  keyId: string;
  /** Открытый ключ (если есть) */
  publicKey?: Uint8Array;
  /** Закрытый ключ (никогда не экспортируется из HSM) */
  privateKey?: Uint8Array;
  /** Алгоритм ключа */
  algorithm: string;
  /** Длина ключа в битах */
  keySize: number;
  /** Время создания */
  createdAt: Date;
}

/**
 * Конфигурация HSM
 */
export interface HSMConfig {
  /** Тип HSM */
  type: KMSProviderType;
  /** Идентификатор провайдера */
  providerId: string;
  /** Конечная точка */
  endpoint?: string;
  /** Регион */
  region?: string;
  /** Учетные данные */
  credentials?: Record<string, string>;
  /** Таймаут в мс */
  timeout: number;
  /** Настройки повторных попыток */
  retryConfig: {
    maxRetries: number;
    initialDelay: number;
    maxDelay: number;
  };
}

/**
 * Информация о ключе HSM
 */
export interface HSMKeyInfo {
  /** Идентификатор ключа */
  keyId: string;
  /** Тип ключа */
  keyType: KeyType;
  /** Алгоритм */
  algorithm: string;
  /** Длина ключа */
  keySize: number;
  /** Статус */
  status: KeyStatus;
  /** Время создания */
  createdAt: Date;
  /** Время последнего использования */
  lastUsedAt?: Date;
  /** Теги */
  tags?: Record<string, string>;
}

/**
 * Параметры для бэкапа ключа
 */
export interface HSMBackup {
  /** Идентификатор ключа */
  keyId: string;
  /** Зашифрованные данные ключа */
  encryptedKeyMaterial: Uint8Array;
  /** Алгоритм шифрования бэкапа */
  backupAlgorithm: string;
  /** Временная метка бэкапа */
  backedUpAt: Date;
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Параметры для восстановления ключа
 */
export interface HSMRestore {
  /** Идентификатор ключа */
  keyId: string;
  /** Зашифрованные данные ключа */
  encryptedKeyMaterial: Uint8Array;
  /** Алгоритм шифрования бэкапа */
  backupAlgorithm: string;
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

// ============================================================================
// ТИПЫ ДЛЯ POST-QUANTUM CRYPTO (ДОПОЛНЕНИЕ)
// ============================================================================

/**
 * Конфигурация постквантовой криптографии
 */
export interface PQConfig {
  /** Включить постквантовую криптографию */
  enabled: boolean;
  /** Алгоритмы KEM */
  kemAlgorithms: PQCAlgorithm[];
  /** Алгоритмы подписей */
  signatureAlgorithms: PQCAlgorithm[];
  /** Гибридный режим (классическая + PQC) */
  hybridMode: boolean;
  /** Использовать liboqs */
  useLibOQS: boolean;
}

/**
 * Параметры PQC ключа с metadata
 */
export interface PQCKeyPairWithMetadata extends PQCKeyPair {
  /** Метаданные ключа */
  metadata?: {
    /** OQS алгоритм */
    oqsAlgorithm?: string;
    /** NIST уровень */
    nistLevel?: number;
    /** Время генерации */
    generatedAt?: Date;
    /** Гибридный режим */
    hybridMode?: boolean;
    /** Классический алгоритм */
    classicAlgorithm?: string;
  };
}

/**
 * Результат PQC подписи
 */
export interface PQSignature {
  /** Подпись */
  signature: Uint8Array;
  /** Алгоритм */
  algorithm: PQCAlgorithm;
  /** Идентификатор ключа */
  keyId: string;
  /** Хэш подписанных данных */
  dataHash: Uint8Array;
  /** Временная метка */
  timestamp: number;
}

/**
 * Результат KEM инкапсуляции с metadata
 */
export interface KEMEncapsulationResultWithMetadata extends KEMEncapsulationResult {
  /** Метаданные */
  metadata?: {
    /** Алгоритм */
    algorithm?: string;
    /** Время инкапсуляции */
    encapsulatedAt?: Date;
    /** Гибридный режим */
    hybridMode?: boolean;
    /** Классический алгоритм */
    classicAlgorithm?: string;
    /** KDF */
    kdf?: string;
  };
}

/**
 * Результат KEM деинкапсуляции с metadata
 */
export interface KEMDecapsulationResultWithMetadata extends KEMDecapsulationResult {
  /** Метаданные */
  metadata?: {
    /** Алгоритм */
    algorithm?: string;
    /** Время деинкапсуляции */
    decapsulatedAt?: Date;
    /** Гибридный режим */
    hybridMode?: boolean;
    /** Классический алгоритм */
    classicAlgorithm?: string;
    /** KDF */
    kdf?: string;
  };
  /** Ошибка (если есть) */
  error?: string;
}

/**
 * Конфигурация KMS провайдера
 */
export interface KMSProviderConfig {
  /** Тип провайдера */
  type: KMSProviderType;
  /** Идентификатор провайдера */
  providerId: string;
  /** Конечная точка (endpoint) */
  endpoint?: string;
  /** Регион */
  region?: string;
  /** Учетные данные */
  credentials?: Record<string, string>;
  /** Таймаут в мс */
  timeout: number;
  /** Настройки повторных попыток */
  retryConfig: {
    maxRetries: number;
    initialDelay: number;
    maxDelay: number;
  };
  /** Дополнительные параметры */
  extra?: Record<string, unknown>;
}

/**
 * Статус подключения к HSM/KMS
 */
export interface KMSConnectionStatus {
  /** Подключено */
  connected: boolean;
  /** Время последнего подключения */
  lastConnected?: Date;
  /** Время последней операции */
  lastOperation?: Date;
  /** Статистика операций */
  stats: {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    averageLatency: number;
  };
  /** Информация о здоровье */
  health: {
    status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
    latency: number;
    errorRate: number;
  };
}

// ============================================================================
// ТИПЫ ДЛЯ ПОСТКВАНТОВОЙ КРИПТОГРАФИИ
// ============================================================================

/**
 * Алгоритмы постквантовой криптографии
 */
export type PQCAlgorithm =
  // KEM (Key Encapsulation Mechanism)
  | 'CRYSTALS-Kyber-512'
  | 'CRYSTALS-Kyber-768'
  | 'CRYSTALS-Kyber-1024'
  | 'NTRU-HPS-2048-509'
  | 'NTRU-HPS-2048-677'
  | 'NTRU-HPS-4096-821'
  | 'SABER-LightSaber'
  | 'SABER-Saber'
  | 'SABER-FireSaber'
  // Подписи
  | 'CRYSTALS-Dilithium-2'
  | 'CRYSTALS-Dilithium-3'
  | 'CRYSTALS-Dilithium-5'
  | 'FALCON-512'
  | 'FALCON-1024'
  | 'SPHINCS+-128s'
  | 'SPHINCS+-192s'
  | 'SPHINCS+-256s';

/**
 * Расширенные алгоритмы PQC (для полной совместимости)
 */
export type PQCAlgorithmExtended = PQCAlgorithm
  | 'NTRU-HPS-2048-509'
  | 'NTRU-HPS-2048-677'
  | 'NTRU-HPS-4096-821'
  | 'SABER-LightSaber'
  | 'SABER-Saber'
  | 'SABER-FireSaber';

/**
 * Тип PQC примитива
 */
export type PQCPrimitiveType = 'KEM' | 'SIGNATURE';

/**
 * Пара ключей PQC
 */
export interface PQCKeyPair {
  /** Открытый ключ */
  publicKey: Uint8Array;
  /** Закрытый ключ */
  privateKey: Uint8Array;
  /** Алгоритм */
  algorithm: PQCAlgorithm;
  /** Тип примитива */
  primitiveType: PQCPrimitiveType;
  /** Идентификатор */
  keyId: string;
  /** Метаданные (опционально) */
  metadata?: {
    /** OQS алгоритм */
    oqsAlgorithm?: string;
    /** NIST уровень */
    nistLevel?: number;
    /** Время генерации */
    generatedAt?: Date;
    /** Гибридный режим */
    hybridMode?: boolean;
    /** Классический алгоритм */
    classicAlgorithm?: string;
  };
}

/**
 * Результат инкапсуляции ключа (KEM)
 */
export interface KEMEncapsulationResult {
  /** Зашифрованный общий секрет (ciphertext) */
  ciphertext: Uint8Array;
  /** Общий секрет (shared secret) */
  sharedSecret: Uint8Array;
  /** Идентификатор ключа */
  keyId: string;
  /** Метаданные (опционально) */
  metadata?: {
    /** Алгоритм */
    algorithm?: string;
    /** Время инкапсуляции */
    encapsulatedAt?: Date;
    /** Гибридный режим */
    hybridMode?: boolean;
    /** Классический алгоритм */
    classicAlgorithm?: string;
    /** KDF */
    kdf?: string;
  };
}

/**
 * Результат деинкапсуляции ключа (KEM)
 */
export interface KEMDecapsulationResult {
  /** Общий секрет (shared secret) */
  sharedSecret: Uint8Array;
  /** Успешность операции */
  success: boolean;
  /** Метаданные (опционально) */
  metadata?: {
    /** Алгоритм */
    algorithm?: string;
    /** Время деинкапсуляции */
    decapsulatedAt?: Date;
    /** Гибридный режим */
    hybridMode?: boolean;
    /** Классический алгоритм */
    classicAlgorithm?: string;
    /** KDF */
    kdf?: string;
  };
  /** Ошибка (если есть) */
  error?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ БЕЗОПАСНОЙ ПАМЯТИ
// ============================================================================

/**
 * Настройки безопасной памяти
 */
export interface SecureMemoryConfig {
  /** Запретить выгрузку на диск (swap) */
  noSwap: boolean;
  /** Автоматическая очистка при освобождении */
  autoZero: boolean;
  /** Защита от копирования */
  preventCopy: boolean;
  /** Использование защищенной памяти OS */
  useProtectedMemory: boolean;
  /** Максимальный размер буфера в байтах */
  maxBufferSize: number;
  /** Время жизни по умолчанию (мс) */
  defaultTTL: number;
}

/**
 * Статистика использования памяти
 */
export interface MemoryStats {
  /** Выделено байт */
  allocated: number;
  /** Максимум выделено */
  peakAllocated: number;
  /** Количество очисток */
  zeroOperations: number;
  /** Ошибки выделения */
  allocationErrors: number;
}

// ============================================================================
// ТИПЫ ДЛЯ ЛОГИРОВАНИЯ И АУДИТА
// ============================================================================

/**
 * Уровни логирования
 */
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'AUDIT';

/**
 * Типы событий для аудита
 */
export type AuditEventType =
  | 'KEY_CREATED'
  | 'KEY_USED'
  | 'KEY_ROTATED'
  | 'KEY_REVOKED'
  | 'KEY_DESTROYED'
  | 'ENCRYPTION_PERFORMED'
  | 'DECRYPTION_PERFORMED'
  | 'SIGNATURE_CREATED'
  | 'SIGNATURE_VERIFIED'
  | 'AUTH_SUCCESS'
  | 'AUTH_FAILURE'
  | 'ACCESS_DENIED'
  | 'CONFIG_CHANGED'
  | 'SECURITY_ALERT'
  | 'KEY_EXPIRED'
  | 'KEY_GENERATION'
  | 'KEM_ENCAPSULATE'
  | 'KEM_DECAPSULATE'
  | 'SIGN'
  | 'VERIFY'
  | 'KEM_ENCAPSULATE_HYBRID'
  | 'KEM_DECAPSULATE_HYBRID'
  | 'SIGN_HYBRID'
  | 'VERIFY_HYBRID'
  | 'HYBRID_ENCRYPT'
  | 'HYBRID_DECRYPT'
  | 'KEY_GENERATION_HYBRID';

/**
 * Событие аудита
 */
export interface AuditEvent {
  /** Идентификатор события */
  eventId: string;
  /** Тип события */
  eventType: AuditEventType;
  /** Временная метка */
  timestamp: Date;
  /** Идентификатор актора */
  actorId?: string;
  /** Идентификатор ресурса */
  resourceId?: string;
  /** Результат операции */
  success: boolean;
  /** IP-адрес */
  ipAddress?: string;
  /** User agent */
  userAgent?: string;
  /** Дополнительные данные */
  metadata?: Record<string, unknown>;
  /** Хэш события для целостности */
  eventHash?: string;
}

/**
 * Конфигурация логирования
 */
export interface LoggingConfig {
  /** Уровень логирования */
  level: LogLevel;
  /** Формат вывода */
  format: 'JSON' | 'TEXT';
  /** Вывод в консоль */
  console: boolean;
  /** Файл логов */
  file?: string;
  /** Максимальный размер файла (байт) */
  maxFileSize?: number;
  /** Количество файлов ротации */
  maxFiles?: number;
  /** Логировать чувствительные данные (запрещено!) */
  logSensitiveData: false; // Всегда false!
  /** Маскировать ключи в логах */
  maskKeys: boolean;
  /** Включить аудит */
  enableAudit: boolean;
}

// ============================================================================
// ОБЪЕДИНЕННЫЕ ТИПЫ КОНФИГУРАЦИИ
// ============================================================================

/**
 * Основная конфигурация криптографического сервиса
 */
export interface CryptoServiceConfig {
  /** Конфигурация безопасной памяти */
  memory: SecureMemoryConfig;
  /** Конфигурация логирования */
  logging: LoggingConfig;
  /** Конфигурация KMS провайдеров */
  kmsProviders: KMSProviderConfig[];
  /** Настройки по умолчанию для KDF */
  defaultKDF: KDFParams;
  /** Настройки по умолчанию для симметричного шифрования */
  defaultSymmetric: {
    algorithm: SymmetricAlgorithm;
    keySize: number;
  };
  /** Настройки по умолчанию для асимметричного шифрования */
  defaultAsymmetric: {
    algorithm: AsymmetricAlgorithm;
  };
  /** Настройки по умолчанию для подписей */
  defaultSignature: {
    algorithm: SignatureAlgorithm;
  };
  /** Разрешенные алгоритмы (whitelist) */
  allowedAlgorithms: {
    symmetric: SymmetricAlgorithm[];
    asymmetric: AsymmetricAlgorithm[];
    signature: SignatureAlgorithm[];
    hash: HashAlgorithm[];
    kdf: KDFAlgorithm[];
    pqc: PQCAlgorithm[];
  };
  /** Настройки ротации ключей */
  keyRotation: {
    /** Автоматическая ротация включена */
    enabled: boolean;
    /** Интервал ротации (мс) */
    interval: number;
    /** Хранить старые ключи для расшифрования */
    keepOldKeys: boolean;
    /** Количество старых версий */
    oldVersionsCount: number;
  };
  /** Настройки безопасности */
  security: {
    /** Защита от timing attacks */
    constantTimeOperations: boolean;
    /** Минимальная энтропия */
    minEntropy: number;
    /** Блокировка после ошибок */
    lockoutAfterFailures: number;
    /** Время блокировки (мс) */
    lockoutDuration: number;
  };
}

/**
 * Конфигурация по умолчанию
 */
export const DEFAULT_CRYPTO_CONFIG: CryptoServiceConfig = {
  memory: {
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024, // 10 MB
    defaultTTL: 60000, // 1 минута
  },
  logging: {
    level: 'INFO',
    format: 'JSON',
    console: true,
    maskKeys: true,
    enableAudit: true,
    logSensitiveData: false,
  },
  kmsProviders: [],
  defaultKDF: {
    algorithm: 'Argon2id',
    argon2: {
      memorySize: 65536, // 64 MB
      iterations: 3,
      parallelism: 4,
      hashLength: 32,
    },
  },
  defaultSymmetric: {
    algorithm: 'AES-256-GCM',
    keySize: 256,
  },
  defaultAsymmetric: {
    algorithm: 'RSA-OAEP-4096',
  },
  defaultSignature: {
    algorithm: 'Ed25519',
  },
  allowedAlgorithms: {
    symmetric: ['AES-256-GCM', 'AES-128-GCM', 'ChaCha20-Poly1305', 'XChaCha20-Poly1305'],
    asymmetric: ['RSA-OAEP-4096', 'RSA-OAEP-2048', 'X25519'],
    signature: ['Ed25519', 'Ed448', 'ECDSA-P256-SHA256', 'RSA-PSS-4096-SHA512'],
    hash: ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512', 'BLAKE2b', 'BLAKE3'],
    kdf: ['Argon2id', 'PBKDF2-SHA256', 'HKDF-SHA256', 'scrypt'],
    pqc: ['CRYSTALS-Kyber-768', 'CRYSTALS-Dilithium-3'],
  },
  keyRotation: {
    enabled: true,
    interval: 90 * 24 * 60 * 60 * 1000, // 90 дней
    keepOldKeys: true,
    oldVersionsCount: 2,
  },
  security: {
    constantTimeOperations: true,
    minEntropy: 256,
    lockoutAfterFailures: 5,
    lockoutDuration: 300000, // 5 минут
  },
};
