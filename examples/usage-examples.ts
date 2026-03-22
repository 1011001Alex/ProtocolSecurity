/**
 * ============================================================================
 * ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ CRYPTO SERVICE
 * ============================================================================
 * Полные примеры для всех основных сценариев использования
 * ============================================================================
 */

import {
  CryptoService,
  initializeCryptoService,
  EncryptionEnvelope,
  KeyGenerationParams,
} from './src/crypto/CryptoService';

// ============================================================================
// ПРИМЕР 1: БАЗОВОЕ ШИФРОВАНИЕ
// ============================================================================

async function example1_basicEncryption() {
  console.log('=== Пример 1: Базовое шифрование ===\n');
  
  // Инициализация сервиса
  const cryptoService = await initializeCryptoService();
  
  try {
    // Генерация мастер-ключа
    const keyResult = await cryptoService.generateKey({
      keyType: 'MASTER_KEY',
      algorithm: 'AES-256-GCM',
      keySize: 256,
      name: 'Example Master Key',
      description: 'Ключ для примера базового шифрования',
      exportable: false,
    } as KeyGenerationParams);
    
    console.log('Ключ сгенерирован:', keyResult.keyId);
    
    // Данные для шифрования
    const secretMessage = 'Это секретное сообщение!';
    
    // Шифрование
    const envelope: EncryptionEnvelope = await cryptoService.encrypt(
      secretMessage,
      keyResult.keyId
    );
    
    console.log('Данные зашифрованы');
    console.log('Envelope ID:', envelope.envelopeId);
    console.log('Алгоритм:', envelope.dataAlgorithm);
    
    // Расшифрование
    const decrypted = await cryptoService.decrypt(envelope);
    const decryptedMessage = new TextDecoder().decode(decrypted);
    
    console.log('Данные расшифрованы:', decryptedMessage);
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ПРИМЕР 2: ЦИФРОВЫЕ ПОДПИСИ
// ============================================================================

async function example2_digitalSignatures() {
  console.log('\n=== Пример 2: Цифровые подписи ===\n');
  
  const cryptoService = await initializeCryptoService();
  
  try {
    // Генерация ключа для подписи (Ed25519)
    const signingKey = await cryptoService.generateKey({
      keyType: 'ASYMMETRIC_SIGN',
      algorithm: 'Ed25519',
      keySize: 256,
      name: 'Example Signing Key',
      exportable: false,
    } as KeyGenerationParams);
    
    console.log('Ключ подписи сгенерирован:', signingKey.keyId);
    
    // Документ для подписи
    const document = 'Важный документ для подписания';
    
    // Создание подписи
    const signature = await cryptoService.sign(document, signingKey.keyId);
    
    console.log('Подпись создана');
    console.log('Алгоритм:', signature.algorithm);
    console.log('Длина подписи:', signature.signature.length, 'байт');
    
    // Верификация подписи
    const verification = await cryptoService.verify(
      document,
      signature.signature,
      signingKey.keyId
    );
    
    console.log('Результат верификации:', verification.valid ? '✓ Валидна' : '✗ Невалидна');
    console.log('Детали:', verification.details);
    
    // Попытка верификации с изменёнными данными
    const tamperedDoc = 'Изменённый документ';
    const tamperedVerification = await cryptoService.verify(
      tamperedDoc,
      signature.signature,
      signingKey.keyId
    );
    
    console.log('Верификация с изменёнными данными:', 
      tamperedVerification.valid ? '✓ Валидна' : '✗ Невалидна');
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ПРИМЕР 3: ДЕРИВАЦИЯ КЛЮЧЕЙ ИЗ ПАРОЛЯ
// ============================================================================

async function example3_keyDerivation() {
  console.log('\n=== Пример 3: Деривация ключей из пароля ===\n');
  
  const cryptoService = await initializeCryptoService();
  
  try {
    const password = 'MySecurePassword123!';
    
    // Деривация ключа с автоматической генерацией соли
    const { key, salt } = cryptoService.deriveKeyWithSalt(password);
    
    console.log('Ключ деривирован');
    console.log('Длина ключа:', key.length, 'байт');
    console.log('Соль:', Buffer.from(salt).toString('hex'));
    
    // Деривация того же ключа с той же солью (должен совпасть)
    const key2 = cryptoService.deriveKey(password, salt);
    
    const keysMatch = key.every((b, i) => b === key2[i]);
    console.log('Ключи совпадают:', keysMatch ? '✓ Да' : '✗ Нет');
    
    // Деривация с другим паролем (должен отличаться)
    const key3 = cryptoService.deriveKey('WrongPassword', salt);
    
    const keysMatch2 = key.every((b, i) => b === key3[i]);
    console.log('Ключи с разным паролем совпадают:', keysMatch2 ? '✓ Да' : '✗ Нет');
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ПРИМЕР 4: РОТАЦИЯ КЛЮЧЕЙ
// ============================================================================

async function example4_keyRotation() {
  console.log('\n=== Пример 4: Ротация ключей ===\n');
  
  const cryptoService = await initializeCryptoService();
  
  try {
    // Создаём ключ
    const key1 = await cryptoService.generateKey({
      keyType: 'MASTER_KEY',
      algorithm: 'AES-256-GCM',
      keySize: 256,
      name: 'Rotatable Key',
      exportable: false,
    } as KeyGenerationParams);
    
    console.log('Первый ключ:', key1.keyId);
    
    // Шифруем данные
    const data = 'Secret data for rotation test';
    const envelope1 = await cryptoService.encrypt(data, key1.keyId);
    
    console.log('Данные зашифрованы первым ключом');
    
    // Ротируем ключ
    const key2 = await cryptoService.rotateKey(key1.keyId);
    
    console.log('Второй ключ (после ротации):', key2.keyId);
    
    // Проверяем статусы
    const key1Status = cryptoService.getKey(key1.keyId);
    const key2Status = cryptoService.getKey(key2.keyId);
    
    console.log('Статус первого ключа:', key1Status?.status);
    console.log('Статус второго ключа:', key2Status?.status);
    
    // Расшифровываем старым ключом (должен работать через историю)
    const decrypted1 = await cryptoService.decrypt(envelope1);
    console.log('Расшифровано старым ключом:', new TextDecoder().decode(decrypted1));
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ПРИМЕР 5: ХЭШИРОВАНИЕ
// ============================================================================

async function example5_hashing() {
  console.log('\n=== Пример 5: Хэширование ===\n');
  
  const cryptoService = await initializeCryptoService();
  
  try {
    const data = 'Данные для хэширования';
    
    // Разные алгоритмы
    const algorithms = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'BLAKE2b'] as const;
    
    for (const algo of algorithms) {
      const hash = cryptoService.hash(data, algo);
      console.log(`${algo}: ${Buffer.from(hash.hash).toString('hex').slice(0, 32)}...`);
    }
    
    // HMAC
    const hmacKey = await cryptoService.generateKey({
      keyType: 'MASTER_KEY',
      algorithm: 'AES-256-GCM',
      keySize: 256,
      name: 'HMAC Key',
      exportable: false,
    } as KeyGenerationParams);
    
    const hmac = cryptoService.hmac(data, hmacKey.keyId, 'SHA-256');
    console.log('\nHMAC-SHA256:', Buffer.from(hmac).toString('hex'));
    
    // Проверка целостности
    const originalHash = cryptoService.hash(data, 'SHA-256');
    const integrityCheck = cryptoService.hashService.verifyIntegrity(
      data,
      originalHash.hash,
      'SHA-256'
    );
    
    console.log('\nЦелостность данных:', integrityCheck.valid ? '✓ Подтверждена' : '✗ Нарушена');
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ПРИМЕР 6: ПОСТКВАНТОВАЯ КРИПТОГРАФИЯ
// ============================================================================

async function example6_postQuantum() {
  console.log('\n=== Пример 6: Постквантовая криптография ===\n');
  
  const cryptoService = await initializeCryptoService();
  
  try {
    // Генерация PQC ключей Kyber
    console.log('Генерация ключей CRYSTALS-Kyber-768...');
    const pqcKeyPair = await cryptoService.generatePQCKey('CRYSTALS-Kyber-768');
    
    console.log('PQC ключ сгенерирован:', pqcKeyPair.keyId);
    console.log('Длина открытого ключа:', pqcKeyPair.publicKey.length, 'байт');
    console.log('Длина закрытого ключа:', pqcKeyPair.privateKey.length, 'байт');
    
    // Инкапсуляция (создание общего секрета)
    console.log('\nИнкапсуляция...');
    const encapsulation = await cryptoService.pqcEncapsulate(
      'CRYSTALS-Kyber-768',
      pqcKeyPair.publicKey
    );
    
    console.log('Ciphertext:', encapsulation.ciphertext.length, 'байт');
    console.log('Shared secret:', encapsulation.sharedSecret.length, 'байт');
    
    // Деинкапсуляция
    console.log('\nДеинкапсуляция...');
    const decapsulation = await cryptoService.pqcDecapsulate(
      'CRYSTALS-Kyber-768',
      pqcKeyPair.privateKey,
      encapsulation.ciphertext
    );
    
    console.log('Успех:', decapsulation.success);
    console.log('Shared secrets совпадают:', 
      encapsulation.sharedSecret.every((b, i) => b === decapsulation.sharedSecret[i]) 
        ? '✓ Да' 
        : '✗ Нет');
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ПРИМЕР 7: СТАТИСТИКА И АУДИТ
// ============================================================================

async function example7_statsAndAudit() {
  console.log('\n=== Пример 7: Статистика и аудит ===\n');
  
  const cryptoService = await initializeCryptoService();
  
  try {
    // Выполняем несколько операций
    await cryptoService.generateKey({
      keyType: 'SYMMETRIC',
      algorithm: 'AES-256-GCM',
      keySize: 256,
      name: 'Key 1',
      exportable: false,
    } as KeyGenerationParams);
    
    await cryptoService.generateKey({
      keyType: 'ASYMMETRIC_SIGN',
      algorithm: 'Ed25519',
      keySize: 256,
      name: 'Key 2',
      exportable: false,
    } as KeyGenerationParams);
    
    cryptoService.hash('test data', 'SHA-256');
    cryptoService.randomBytes(32);
    
    // Получаем статистику
    const stats = cryptoService.getStats();
    
    console.log('Статистика операций:');
    console.log('- Всего операций:', stats.operations.totalOperations);
    console.log('- Успешных:', stats.operations.successfulOperations);
    console.log('- Ошибок:', stats.operations.failedOperations);
    console.log('- Среднее время (ms):', stats.operations.averageLatency.toFixed(2));
    
    console.log('\nСтатистика ключей:');
    console.log('- Всего ключей:', stats.keys.totalKeys);
    console.log('- Активных:', stats.keys.keysByStatus.ACTIVE);
    console.log('- Симметричных:', stats.keys.keysByType.SYMMETRIC);
    console.log('- Асимметричных:', stats.keys.keysByType.ASYMMETRIC_SIGN);
    
    // Получаем журнал аудита
    const auditLog = cryptoService.getAuditLog(5);
    
    console.log('\nПоследние события аудита:');
    for (const event of auditLog) {
      console.log(`- [${event.eventType}] ${event.success ? '✓' : '✗'} ${event.timestamp.toISOString()}`);
    }
    
  } finally {
    await cryptoService.destroy();
  }
}

// ============================================================================
// ЗАПУСК ВСЕХ ПРИМЕРОВ
// ============================================================================

async function runAllExamples() {
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║   PROTOCOL CRYPTO SERVICE - ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ        ║');
  console.log('╚═══════════════════════════════════════════════════════════╝\n');
  
  try {
    await example1_basicEncryption();
    await example2_digitalSignatures();
    await example3_keyDerivation();
    await example4_keyRotation();
    await example5_hashing();
    await example6_postQuantum();
    await example7_statsAndAudit();
    
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║              ВСЕ ПРИМЕРЫ ВЫПОЛНЕНЫ УСПЕШНО               ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    
  } catch (error) {
    console.error('\n❌ Ошибка при выполнении примеров:', error);
  }
}

// Запуск если файл запущен напрямую
if (typeof require !== 'undefined' && require.main === module) {
  runAllExamples();
}

// Экспорт для использования в других модулях
export { runAllExamples };
