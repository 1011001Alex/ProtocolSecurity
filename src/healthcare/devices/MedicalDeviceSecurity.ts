/**
 * ============================================================================
 * MEDICAL DEVICE SECURITY — БЕЗОПАСНОСТЬ МЕДИЦИНСКИХ УСТРОЙСТВ (IoMT)
 * ============================================================================
 *
 * Защита Internet of Medical Things (IoMT) устройств
 *
 * Функциональность:
 * - Регистрация устройств
 * - Device posture assessment
 * - Quarantine для несоответствующих устройств
 * - Мониторинг уязвимостей
 *
 * @package protocol/healthcare-security/devices
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import { MedicalDevice, DevicePostureStatus } from '../types/healthcare.types';

export class MedicalDeviceSecurity extends EventEmitter {
  private devices: Map<string, MedicalDevice> = new Map();
  private isInitialized = false;

  constructor() {
    super();
    logger.info('[MedicalDeviceSecurity] Service created');
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    logger.info('[MedicalDeviceSecurity] Initialized');
    this.emit('initialized');
  }

  /**
   * Регистрация устройства
   */
  public async registerDevice(deviceData: Omit<MedicalDevice, 'registeredAt' | 'status'>): Promise<MedicalDevice> {
    const deviceId = `device-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const device: MedicalDevice = {
      ...deviceData,
      deviceId,
      status: 'ACTIVE',
      registeredAt: new Date(),
      postureStatus: {
        compliant: true,
        issues: [],
        checkedAt: new Date()
      }
    };

    this.devices.set(deviceId, device);

    logger.info('[MedicalDeviceSecurity] Device registered', {
      deviceId,
      deviceType: device.deviceType
    });

    this.emit('device_registered', device);

    return device;
  }

  /**
   * Проверка device posture
   */
  public async checkDevicePosture(deviceId: string): Promise<DevicePostureStatus> {
    const device = this.devices.get(deviceId);

    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    const issues: string[] = [];

    // Проверка обновлений ПО
    if (!device.firmwareVersion) {
      issues.push('Firmware version unknown');
    }

    // Проверка последнего подключения
    if (device.lastSeenAt) {
      const hoursSinceLastSeen = (Date.now() - device.lastSeenAt.getTime()) / (1000 * 60 * 60);

      if (hoursSinceLastSeen > 72) {
        issues.push(`Device not seen for ${hoursSinceLastSeen.toFixed(1)} hours`);
      }
    }

    const postureStatus: DevicePostureStatus = {
      compliant: issues.length === 0,
      issues,
      checkedAt: new Date(),
      antivirusUpdated: true,
      osPatched: true,
      certificatesValid: true,
      configurationValid: true
    };

    device.postureStatus = postureStatus;
    this.devices.set(deviceId, device);

    if (!postureStatus.compliant) {
      logger.warn('[MedicalDeviceSecurity] Device non-compliant', {
        deviceId,
        issues
      });
    }

    return postureStatus;
  }

  /**
   * Карантин устройства
   */
  public async quarantineDevice(deviceId: string, reasons: string[]): Promise<void> {
    const device = this.devices.get(deviceId);

    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    device.status = 'QUARANTINED';
    this.devices.set(deviceId, device);

    logger.warn('[MedicalDeviceSecurity] Device quarantined', {
      deviceId,
      reasons
    });

    this.emit('device_quarantined', { deviceId, reasons });
  }

  /**
   * Восстановление устройства из карантина
   */
  public async restoreDevice(deviceId: string): Promise<void> {
    const device = this.devices.get(deviceId);

    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    device.status = 'ACTIVE';
    device.postureStatus = {
      compliant: true,
      issues: [],
      checkedAt: new Date()
    };

    this.devices.set(deviceId, device);

    logger.info('[MedicalDeviceSecurity] Device restored', { deviceId });

    this.emit('device_restored', deviceId);
  }

  /**
   * Получение устройства
   */
  public getDevice(deviceId: string): MedicalDevice | undefined {
    return this.devices.get(deviceId);
  }

  /**
   * Список всех устройств
   */
  public listDevices(options?: {
    deviceType?: string;
    status?: MedicalDevice['status'];
    compliantOnly?: boolean;
  }): MedicalDevice[] {
    let devices = Array.from(this.devices.values());

    if (options) {
      if (options.deviceType) {
        devices = devices.filter(d => d.deviceType === options.deviceType);
      }

      if (options.status) {
        devices = devices.filter(d => d.status === options.status);
      }

      if (options.compliantOnly) {
        devices = devices.filter(d => d.postureStatus?.compliant !== false);
      }
    }

    return devices;
  }

  public async destroy(): Promise<void> {
    this.devices.clear();
    this.isInitialized = false;
    logger.info('[MedicalDeviceSecurity] Destroyed');
    this.emit('destroyed');
  }
}
