/**
 * ============================================================================
 * ROYALTY ENFORCER — ПРИНУДИТЕЛЬНОЕ ВЗЫСКАНИЕ РОЯЛТИ
 * ============================================================================
 *
 * NFT royalty enforcement
 *
 * @package protocol/blockchain-security/nft
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';

export class RoyaltyEnforcer extends EventEmitter {
  private isInitialized = false;
  private royaltyConfigs: Map<string, { percentage: number; recipient: string }> = new Map();
  private readonly config: {
    enforcement: string;
  };

  constructor(config: { royaltyEnforcement: string }) {
    super();
    this.config = { enforcement: config.royaltyEnforcement };
    logger.info('[RoyaltyEnforcer] Service created', { enforcement: this.config.enforcement });
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    logger.info('[RoyaltyEnforcer] Initialized');
    this.emit('initialized');
  }

  /**
   * Установка роялти для коллекции
   */
  public async setRoyalty(
    contractAddress: string,
    percentage: number,
    recipient: string
  ): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('RoyaltyEnforcer not initialized');
    }

    if (percentage < 0 || percentage > 50) {
      throw new Error('Royalty percentage must be between 0 and 50');
    }

    this.royaltyConfigs.set(contractAddress.toLowerCase(), {
      percentage,
      recipient
    });

    logger.info('[RoyaltyEnforcer] Royalty configured', {
      contractAddress,
      percentage,
      recipient
    });

    this.emit('royalty_configured', { contractAddress, percentage, recipient });
  }

  /**
   * Расчёт роялти
   */
  public async calculateRoyalty(
    contractAddress: string,
    salePrice: number
  ): Promise<{
    royaltyAmount: number;
    recipient: string;
    percentage: number;
  }> {
    const config = this.royaltyConfigs.get(contractAddress.toLowerCase());

    if (!config) {
      return {
        royaltyAmount: 0,
        recipient: '',
        percentage: 0
      };
    }

    const royaltyAmount = (salePrice * config.percentage) / 100;

    return {
      royaltyAmount,
      recipient: config.recipient,
      percentage: config.percentage
    };
  }

  /**
   * Принудительное взыскание роялти
   */
  public async enforceRoyalty(sale: {
    contractAddress: string;
    tokenId: string;
    salePrice: number;
    seller: string;
    marketplace: string;
  }): Promise<{
    enforced: boolean;
    royaltyAmount: number;
    recipient: string;
  }> {
    if (this.config.enforcement === 'NONE') {
      return {
        enforced: false,
        royaltyAmount: 0,
        recipient: ''
      };
    }

    const royalty = await this.calculateRoyalty(sale.contractAddress, sale.salePrice);

    if (royalty.percentage === 0) {
      return {
        enforced: false,
        royaltyAmount: 0,
        recipient: ''
      };
    }

    logger.info('[RoyaltyEnforcer] Royalty enforced', {
      contractAddress: sale.contractAddress,
      tokenId: sale.tokenId,
      royaltyAmount: royalty.recipient
    });

    this.emit('royalty_enforced', {
      ...sale,
      ...royalty
    });

    return {
      enforced: true,
      royaltyAmount: royalty.royaltyAmount,
      recipient: royalty.recipient
    };
  }

  /**
   * Получение информации о роялти
   */
  public getRoyaltyInfo(contractAddress: string): {
    percentage: number;
    recipient: string;
    configured: boolean;
  } {
    const config = this.royaltyConfigs.get(contractAddress.toLowerCase());

    return {
      percentage: config?.percentage || 0,
      recipient: config?.recipient || '',
      configured: !!config
    };
  }

  public async destroy(): Promise<void> {
    this.royaltyConfigs.clear();
    this.isInitialized = false;
    logger.info('[RoyaltyEnforcer] Destroyed');
    this.emit('destroyed');
  }
}
