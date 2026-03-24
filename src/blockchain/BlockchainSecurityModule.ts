/**
 * ============================================================================
 * BLOCKCHAIN SECURITY MODULE - ГЛАВНЫЙ МОДУЛЬ
 * ============================================================================
 *
 * Web3 / Blockchain Security Branch
 *
 * @package protocol/blockchain-security
 */

import { EventEmitter } from 'events';
import { logger } from '../utils/StubLogger';
import { BlockchainSecurityConfig } from './types/blockchain.types';
import { PostQuantumSigner } from './crypto/PostQuantumSigner';
import { ZKAuthenticator } from './zk/ZKAuthenticator';
import { MEVProtector } from './mev/MEVProtector';
import { FormalVerifier } from './contracts/FormalVerifier';
import { BridgeSecurity } from './bridge/BridgeSecurity';
import { NFTAuthenticator } from './nft/NFTAuthenticator';
import { RoyaltyEnforcer } from './nft/RoyaltyEnforcer';

/**
 * Blockchain Security Module
 */
export class BlockchainSecurityModule extends EventEmitter {
  /** Конфигурация */
  private readonly config: BlockchainSecurityConfig;

  /** Post-Quantum Cryptography */
  public readonly postQuantum: PostQuantumSigner;

  /** Zero-Knowledge Authentication */
  public readonly zkAuth: ZKAuthenticator;

  /** MEV Protection */
  public readonly mevProtection: MEVProtector;

  /** Smart Contract Verification */
  public readonly contractVerifier: FormalVerifier;

  /** Cross-Chain Bridge Security */
  public readonly bridgeSecurity: BridgeSecurity;

  /** NFT Authentication */
  public readonly nftAuth: NFTAuthenticator;

  /** Royalty Enforcement */
  public readonly royaltyEnforcer: RoyaltyEnforcer;

  /** Статус инициализации */
  private isInitialized = false;

  /**
   * Создаёт новый экземпляр BlockchainSecurityModule
   */
  constructor(config: BlockchainSecurityConfig) {
    super();

    this.config = {
      postQuantum: config.postQuantum ?? { enabled: true, algorithm: 'CRYSTALS-Dilithium', hybridMode: true },
      zeroKnowledge: config.zeroKnowledge ?? { enabled: true, provider: 'circom', proofSystem: 'Groth16' },
      mevProtection: config.mevProtection ?? { enabled: true, mode: 'AGGRESSIVE', flashbotsEnabled: true, commitRevealEnabled: true },
      contractVerification: config.contractVerification ?? { enabled: true, prover: 'Z3', autoVerify: true },
      bridgeSecurity: config.bridgeSecurity ?? { enabled: true, zkVerification: true, multiSigThreshold: '5-of-9', insuranceEnabled: true },
      nftSecurity: config.nftSecurity ?? { enabled: true, provenanceTracking: true, royaltyEnforcement: 'ON_CHAIN' }
    };

    // Инициализация подмодулей
    this.postQuantum = new PostQuantumSigner(this.config.postQuantum);
    this.zkAuth = new ZKAuthenticator(this.config.zeroKnowledge);
    this.mevProtection = new MEVProtector(this.config.mevProtection);
    this.contractVerifier = new FormalVerifier(this.config.contractVerification);
    this.bridgeSecurity = new BridgeSecurity(this.config.bridgeSecurity);
    this.nftAuth = new NFTAuthenticator(this.config.nftSecurity);
    this.royaltyEnforcer = new RoyaltyEnforcer(this.config.nftSecurity);

    logger.info('[BlockchainSecurity] Module created', {
      postQuantumEnabled: this.config.postQuantum.enabled,
      zkEnabled: this.config.zeroKnowledge.enabled,
      mevProtectionEnabled: this.config.mevProtection.enabled
    });
  }

  /**
   * Инициализация модуля
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[BlockchainSecurity] Already initialized');
      return;
    }

    try {
      await this.postQuantum.initialize();
      await this.zkAuth.initialize();
      await this.mevProtection.initialize();
      await this.contractVerifier.initialize();
      await this.bridgeSecurity.initialize();
      await this.nftAuth.initialize();
      await this.royaltyEnforcer.initialize();

      this.isInitialized = true;

      logger.info('[BlockchainSecurity] Module fully initialized');
      this.emit('initialized');

    } catch (error) {
      logger.error('[BlockchainSecurity] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Проверка инициализации
   */
  public isReady(): boolean {
    return this.isInitialized;
  }

  /**
   * Остановка модуля
   */
  public async destroy(): Promise<void> {
    logger.info('[BlockchainSecurity] Shutting down...');

    await this.postQuantum.destroy();
    await this.zkAuth.destroy();
    await this.mevProtection.destroy();
    await this.contractVerifier.destroy();
    await this.bridgeSecurity.destroy();
    await this.nftAuth.destroy();
    await this.royaltyEnforcer.destroy();

    this.isInitialized = false;

    logger.info('[BlockchainSecurity] Module shut down');
    this.emit('destroyed');
  }
}

/**
 * Factory для создания Blockchain Security Module
 */
export function createBlockchainSecurityModule(config: BlockchainSecurityConfig): BlockchainSecurityModule {
  return new BlockchainSecurityModule(config);
}
