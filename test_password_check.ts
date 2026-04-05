import { createPasswordService } from './src/auth/PasswordService';

const ps = createPasswordService({ algorithm: 'argon2id', memoryCost: 65536, timeCost: 3, parallelism: 4 });

const passwords = [
  'SecurePassword123!',
  'AnotherPassword123!',
  'TestPassword123!',
  'login@example.com',  // possible email as password
  'password123',
];

for (const p of passwords) {
  const r = ps.validatePasswordStrength(p);
  console.log(`Password: "${p}"`);
  console.log(`  valid: ${r.valid}`);
  console.log(`  score: ${r.score}`);
  console.log(`  requirements: ${JSON.stringify(r.requirements)}`);
  console.log(`  warnings: ${JSON.stringify(r.warnings)}`);
  console.log('');
}
