/**
 * ============================================================================
 * BLOCKCHAIN SECURITY MODULE - ЭКСПОРТЫ
 * ============================================================================
 *
 * Web3 / Blockchain Security Branch
 *
 * Components:
 * - Post-Quantum Cryptography (CRYSTALS-Dilithium)
 * - Zero-Knowledge Proofs
 * - MEV Protection
 * - Smart Contract Formal Verification
 * - Cross-Chain Bridge Security
 * - NFT Authentication
 *
 * @package protocol/blockchain-security
 * @author Protocol Security Team
 * @version 1.0.0
 */

// Main Module
export { BlockchainSecurityModule, createBlockchainSecurityModule } from './BlockchainSecurityModule';
export type { BlockchainSecurityConfig } from './types/blockchain.types';

// Post-Quantum Cryptography
export { PostQuantumSigner } from './crypto/PostQuantumSigner';

// Zero-Knowledge Authentication
export { ZKAuthenticator } from './zk/ZKAuthenticator';

// MEV Protection
export { MEVProtector } from './mev/MEVProtector';

// Smart Contract Verification
export { FormalVerifier } from './contracts/FormalVerifier';

// Cross-Chain Security
export { BridgeSecurity } from './bridge/BridgeSecurity';

// NFT Security
export { NFTAuthenticator } from './nft/NFTAuthenticator';
export { RoyaltyEnforcer } from './nft/RoyaltyEnforcer';
