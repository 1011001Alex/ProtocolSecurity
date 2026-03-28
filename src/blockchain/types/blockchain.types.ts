/**
 * ============================================================================
 * BLOCKCHAIN SECURITY TYPES & INTERFACES
 * ============================================================================
 *
 * Типы и интерфейсы для Blockchain Security Branch
 *
 * @package protocol/blockchain-security
 * @author Protocol Security Team
 * @version 1.0.0
 */

/**
 * Конфигурация Blockchain Security Module
 */
export interface BlockchainSecurityConfig {
  /** Post-Quantum Cryptography настройки */
  postQuantum: {
    enabled: boolean;
    algorithm: 'CRYSTALS-Dilithium' | 'CRYSTALS-Kyber' | 'FALCON' | 'SPHINCS+';
    hybridMode: boolean; // ECDSA + PQC
  };

  /** Zero-Knowledge настройки */
  zeroKnowledge: {
    enabled: boolean;
    provider: 'circom' | 'snarkjs' | 'halo2' | 'custom';
    proofSystem: 'groth16' | 'plonk' | 'halo2';
  };

  /** MEV Protection настройки */
  mevProtection: {
    enabled: boolean;
    mode: 'PASSIVE' | 'AGGRESSIVE' | 'PARANOID';
    flashbotsEnabled: boolean;
    commitRevealEnabled: boolean;
  };

  /** Smart Contract Verification */
  contractVerification: {
    enabled: boolean;
    prover: 'Z3' | 'CVC5' | 'Boogie';
    autoVerify: boolean;
  };

  /** Cross-Chain Bridge Security */
  bridgeSecurity: {
    enabled: boolean;
    zkVerification: boolean;
    multiSigThreshold: string; // "5-of-9"
    insuranceEnabled: boolean;
  };

  /** NFT Security */
  nftSecurity: {
    enabled: boolean;
    provenanceTracking: boolean;
    royaltyEnforcement: 'NONE' | 'ON_CHAIN' | 'OFF_CHAIN';
  };
}

/**
 * Blockchain сеть
 */
export type BlockchainNetwork =
  | 'ETHEREUM'
  | 'POLYGON'
  | 'BSC'
  | 'AVALANCHE'
  | 'ARBITRUM'
  | 'OPTIMISM'
  | 'SOLANA'
  | 'COSMOS'
  | 'POLKADOT'
  | 'NEAR'
  | 'CARDANO';

/**
 * Post-Quantum signature результат
 */
export interface PQSignature {
  /** Signature bytes (hex) */
  signature: string;

  /** Public key (hex) */
  publicKey: string;

  /** Algorithm used */
  algorithm: string;

  /** Hybrid signature (ECDSA + PQC) */
  hybrid?: {
    ecdsaSignature: string;
    pqcSignature: string;
    combinedHash?: string;
  };

  /** Timestamp */
  timestamp: Date;
}

/**
 * Zero-Knowledge proof результат
 */
export interface ZKProof {
  /** Proof bytes (hex) */
  proof: string;

  /** Public inputs */
  publicInputs: string[];

  /** Proof system */
  proofSystem: string;

  /** Verification key hash */
  verificationKeyHash: string;

  /** Timestamp */
  timestamp: Date;

  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * ZK Authentication результат
 */
export interface ZKAuthResult {
  /** Authentication successful */
  authenticated: boolean;

  /** ZK Proof */
  proof: ZKProof;

  /** Wallet address */
  wallet: string;

  /** Biometric verified */
  biometricVerified: boolean;

  /** FIDO2 verified */
  fido2Verified: boolean;

  /** Timestamp */
  timestamp: Date;

  /** Verification time in ms */
  verificationTime?: number;
}

/**
 * MEV Protection результат
 */
export interface MEVProtectionResult {
  /** Transaction ID */
  txId: string;

  /** MEV risk score (0-1) */
  mevRiskScore: number;

  /** MEV type detected */
  mevType: 'NONE' | 'FRONTRUNNING' | 'BACKRUNNING' | 'SANDWICH' | 'TIME_BANDIT';

  /** Protection applied */
  protectionApplied: string[];

  /** Recommended action */
  recommendedAction: 'PROCEED' | 'USE_PRIVATE_RPC' | 'COMMIT_REVEAL' | 'DELAY';

  /** Estimated MEV loss prevented (USD) */
  estimatedLossPrevented: number;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Smart Contract verification результат
 */
export interface ContractVerificationResult {
  /** Contract address */
  contractAddress: string;

  /** Verification passed */
  verified: boolean;

  /** Security score (0-100) */
  securityScore: number;

  /** Vulnerabilities found */
  vulnerabilities: ContractVulnerability[];

  /** Formal verification result */
  formalVerification: {
    passed: boolean;
    propertiesVerified: string[];
    counterExamples?: string[];
  };

  /** Gas optimization suggestions */
  gasOptimizations: string[];

  /** Timestamp */
  timestamp: Date;
}

/**
 * Contract vulnerability
 */
export interface ContractVulnerability {
  /** Vulnerability type */
  type: 'REENTRANCY' | 'OVERFLOW' | 'UNDERFLOW' | 'ACCESS_CONTROL' | 'LOGIC_ERROR' | 'ORACLE_MANIPULATION' | 'FLASH_LOAN' | 'FRONTRUNNABLE';

  /** Severity */
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

  /** Location in code */
  location: {
    file: string;
    line: number;
    function: string;
  };

  /** Description */
  description: string;

  /** Recommendation */
  recommendation: string;

  /** CWE ID */
  cweId?: string;
}

/**
 * Cross-Chain Bridge transaction
 */
export interface BridgeTransaction {
  /** Transaction ID */
  txId: string;

  /** Source chain */
  sourceChain: BlockchainNetwork;

  /** Destination chain */
  destinationChain: BlockchainNetwork;

  /** Amount */
  amount: string;

  /** Token */
  token: string;

  /** Sender */
  sender: string;

  /** Recipient */
  recipient: string;

  /** ZK Proof (если есть) */
  zkProof?: ZKProof;

  /** Multi-Sig approvals */
  multisigApprovals: {
    required: number;
    received: number;
    approvers: string[];
  };

  /** Status */
  status: 'PENDING' | 'VERIFYING' | 'APPROVED' | 'REJECTED' | 'COMPLETED' | 'FAILED';

  /** Timestamp */
  timestamp: Date;
}

/**
 * NFT Provenance данные
 */
export interface NFTProvenance {
  /** Token ID */
  tokenId: string;

  /** Contract address */
  contractAddress: string;

  /** Chain */
  chain: BlockchainNetwork;

  /** Creator */
  creator: string;

  /** Current owner */
  currentOwner: string;

  /** Ownership history */
  ownershipHistory: {
    owner: string;
    acquiredAt: Date;
    transferredAt?: Date;
    price?: string;
    txHash?: string;
  }[];

  /** Authenticity verified */
  authenticityVerified: boolean;

  /** Royalty info */
  royaltyInfo?: {
    percentage: number;
    recipient: string;
    enforced: boolean;
  };

  /** Metadata hash */
  metadataHash: string;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Smart Contract Security Audit результат
 */
export interface ContractAuditResult {
  /** Contract name */
  contractName: string;

  /** Audit date */
  auditDate: Date;

  /** Overall score */
  overallScore: number;

  /** Security issues */
  issues: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };

  /** Categories */
  categories: {
    accessControl: number;
    arithmetic: number;
    reentrancy: number;
    oracle: number;
    gasOptimization: number;
    codeQuality: number;
  };

  /** Recommendations */
  recommendations: string[];

  /** Audit firm */
  auditFirm?: string;

  /** Report URL */
  reportUrl?: string;
}

/**
 * DeFi Protocol Security Assessment
 */
export interface DeFiSecurityAssessment {
  /** Protocol name */
  protocolName: string;

  /** TVL (Total Value Locked) */
  tvl: number;

  /** Security score */
  securityScore: number;

  /** Risk factors */
  riskFactors: {
    smartContractRisk: 'LOW' | 'MEDIUM' | 'HIGH';
    oracleRisk: 'LOW' | 'MEDIUM' | 'HIGH';
    governanceRisk: 'LOW' | 'MEDIUM' | 'HIGH';
    liquidityRisk: 'LOW' | 'MEDIUM' | 'HIGH';
    regulatoryRisk: 'LOW' | 'MEDIUM' | 'HIGH';
  };

  /** Audits completed */
  audits: ContractAuditResult[];

  /** Insurance coverage */
  insuranceCoverage?: {
    provider: string;
    coverageAmount: number;
  };

  /** Recommendations */
  recommendations: string[];
}

/**
 * Wallet Security Assessment
 */
export interface WalletSecurityAssessment {
  /** Wallet address */
  wallet: string;

  /** Security score */
  securityScore: number;

  /** Risk indicators */
  riskIndicators: {
    isContract: boolean;
    isMultisig: boolean;
    hasInteractedWithSuspiciousContracts: boolean;
    hasApprovedUnlimitedAllowances: boolean;
    hasExposedPrivateKey: boolean;
    ageInDays: number;
    transactionCount: number;
  };

  /** Suspicious approvals */
  suspiciousApprovals: {
    token: string;
    spender: string;
    amount: string;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }[];

  /** Recommendations */
  recommendations: string[];
}

/**
 * Transaction Security Check результат
 */
export interface TransactionSecurityCheck {
  /** Transaction hash */
  txHash: string;

  /** Security score */
  securityScore: number;

  /** Risk level */
  riskLevel: 'SAFE' | 'CAUTION' | 'RISKY' | 'DANGEROUS';

  /** Checks performed */
  checks: {
    contractVerified: boolean;
    noReentrancy: boolean;
    noUnlimitedApproval: boolean;
    noKnownExploit: boolean;
    reasonableGasPrice: boolean;
  };

  /** Warnings */
  warnings: string[];

  /** Recommendations */
  recommendations: string[];
}
