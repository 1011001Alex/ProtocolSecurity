/**
 * =============================================================================
 * RBAC (ROLE-BASED ACCESS CONTROL) SERVICE
 * =============================================================================
 * Сервис для управления ролями и проверке разрешений
 * Поддерживает: иерархию ролей, наследование разрешений, ограничения
 * Соответствует: NIST RBAC standards
 * =============================================================================
 */

import { v4 as uuidv4 } from 'uuid';
import {
  IRole,
  IRoleAssignment,
  IRoleConstraints,
  IUser,
  AccessCheckResult,
  AuthError,
  AuthErrorCode,
} from '../types/auth.types';

/**
 * Конфигурация RBAC сервиса
 */
export interface RBACServiceConfig {
  /** Префикс для ключей хранилища */
  keyPrefix: string;
  
  /** Разрешить ли наследование ролей */
  enableRoleInheritance: boolean;
  
  /** Проверять ли ограничения ролей */
  enableRoleConstraints: boolean;
  
  /** Кэшировать ли результаты проверок */
  enableCaching: boolean;
  
  /** TTL кэша (секунды) */
  cacheTTL: number;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: RBACServiceConfig = {
  keyPrefix: 'protocol:rbac:',
  enableRoleInheritance: true,
  enableRoleConstraints: true,
  enableCaching: true,
  cacheTTL: 300, // 5 минут
};

/**
 * Встроенные системные роли
 */
const SYSTEM_ROLES: Record<string, Partial<IRole>> = {
  'superadmin': {
    name: 'superadmin',
    description: 'Полный доступ ко всем ресурсам системы',
    permissions: ['*:*:*'], // Wildcard для всех разрешений
    isSystem: true,
  },
  'admin': {
    name: 'admin',
    description: 'Администратор системы',
    permissions: [
      'users:read', 'users:write', 'users:delete',
      'roles:read', 'roles:write',
      'settings:read', 'settings:write',
      'logs:read',
      'audit:read',
    ],
    isSystem: true,
  },
  'moderator': {
    name: 'moderator',
    description: 'Модератор контента',
    permissions: [
      'content:read', 'content:write', 'content:delete',
      'users:read',
      'reports:read', 'reports:write',
    ],
    isSystem: true,
  },
  'user': {
    name: 'user',
    description: 'Обычный пользователь',
    permissions: [
      'profile:read', 'profile:write',
      'content:read', 'content:write',
    ],
    isSystem: true,
  },
  'guest': {
    name: 'guest',
    description: 'Гость (минимальные права)',
    permissions: [
      'public:read',
    ],
    isSystem: true,
  },
};

/**
 * Кэш разрешений
 */
interface PermissionCache {
  permissions: Set<string>;
  expiresAt: number;
}

/**
 * =============================================================================
 * RBAC SERVICE CLASS
 * =============================================================================
 */
export class RBACService {
  private config: RBACServiceConfig;
  private roles: Map<string, IRole> = new Map();
  private roleAssignments: Map<string, IRoleAssignment[]> = new Map();
  private permissionCache: Map<string, PermissionCache> = new Map();

  /**
   * Создает новый экземпляр RBACService
   * @param config - Конфигурация сервиса
   */
  constructor(config: RBACServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
    this.initializeSystemRoles();
  }

  /**
   * Инициализирует системные роли
   * @private
   */
  private initializeSystemRoles(): void {
    for (const [id, roleData] of Object.entries(SYSTEM_ROLES)) {
      const role: IRole = {
        id,
        name: roleData.name!,
        description: roleData.description,
        parentRoles: [],
        permissions: roleData.permissions || [],
        constraints: {},
        createdAt: new Date(),
        updatedAt: new Date(),
        isSystem: roleData.isSystem || false,
      };
      this.roles.set(id, role);
    }
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ РОЛЯМИ
  // ===========================================================================

  /**
   * Создает новую роль
   * @param name - Название роли
   * @param permissions - Разрешения
   * @param options - Дополнительные опции
   * @returns Созданная роль
   */
  public createRole(
    name: string,
    permissions: string[] = [],
    options?: {
      description?: string;
      parentRoles?: string[];
      constraints?: IRoleConstraints;
    }
  ): IRole {
    // Проверка уникальности имени
    if (this.getRoleByName(name)) {
      throw new AuthError(
        `Роль с именем "${name}" уже существует`,
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        400
      );
    }

    const role: IRole = {
      id: uuidv4(),
      name,
      description: options?.description,
      parentRoles: options?.parentRoles || [],
      permissions,
      constraints: options?.constraints || {},
      createdAt: new Date(),
      updatedAt: new Date(),
      isSystem: false,
    };

    this.roles.set(role.id, role);
    return role;
  }

  /**
   * Обновляет роль
   * @param roleId - ID роли
   * @param updates - Обновления
   * @returns Обновленная роль
   */
  public updateRole(
    roleId: string,
    updates: Partial<Pick<IRole, 'name' | 'description' | 'permissions' | 'constraints'>>
  ): IRole {
    const role = this.getRoleById(roleId);
    if (!role) {
      throw new AuthError(
        'Роль не найдена',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        404
      );
    }

    if (role.isSystem) {
      throw new AuthError(
        'Системные роли нельзя изменять',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        403
      );
    }

    // Проверка уникальности имени при изменении
    if (updates.name && updates.name !== role.name) {
      const existingRole = this.getRoleByName(updates.name);
      if (existingRole && existingRole.id !== roleId) {
        throw new AuthError(
          `Роль с именем "${updates.name}" уже существует`,
          AuthErrorCode.INSUFFICIENT_PERMISSIONS,
          400
        );
      }
    }

    Object.assign(role, {
      ...updates,
      updatedAt: new Date(),
    });

    // Очистка кэша для всех пользователей с этой ролью
    this.clearPermissionCacheForRole(roleId);

    return role;
  }

  /**
   * Удаляет роль
   * @param roleId - ID роли
   */
  public deleteRole(roleId: string): void {
    const role = this.getRoleById(roleId);
    if (!role) {
      throw new AuthError(
        'Роль не найдена',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        404
      );
    }

    if (role.isSystem) {
      throw new AuthError(
        'Системные роли нельзя удалять',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        403
      );
    }

    // Проверка на использование роли
    const assignments = this.getRoleAssignmentsByRole(roleId);
    if (assignments.length > 0) {
      throw new AuthError(
        'Нельзя удалить роль, которая назначена пользователям',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        400
      );
    }

    // Проверка на зависимость от других ролей
    for (const r of this.roles.values()) {
      if (r.parentRoles.includes(roleId)) {
        throw new AuthError(
          'Нельзя удалить роль, от которой зависят другие роли',
          AuthErrorCode.INSUFFICIENT_PERMISSIONS,
          400
        );
      }
    }

    this.roles.delete(roleId);
  }

  /**
   * Получает роль по ID
   * @param roleId - ID роли
   * @returns Роль или null
   */
  public getRoleById(roleId: string): IRole | null {
    return this.roles.get(roleId) || null;
  }

  /**
   * Получает роль по имени
   * @param name - Название роли
   * @returns Роль или null
   */
  public getRoleByName(name: string): IRole | null {
    for (const role of this.roles.values()) {
      if (role.name === name) {
        return role;
      }
    }
    return null;
  }

  /**
   * Получает все роли
   * @returns Массив ролей
   */
  public getAllRoles(): IRole[] {
    return Array.from(this.roles.values());
  }

  // ===========================================================================
  // НАЗНАЧЕНИЕ РОЛЕЙ
  // ===========================================================================

  /**
   * Назначает роль пользователю
   * @param userId - ID пользователя
   * @param roleId - ID роли
   * @param assignedBy - Кто назначил
   * @param options - Дополнительные опции
   * @returns Назначение роли
   */
  public assignRole(
    userId: string,
    roleId: string,
    assignedBy: string,
    options?: {
      expiresAt?: Date;
      reason?: string;
    }
  ): IRoleAssignment {
    const role = this.getRoleById(roleId);
    if (!role) {
      throw new AuthError(
        'Роль не найдена',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        404
      );
    }

    // Проверка ограничений роли
    if (this.config.enableRoleConstraints && role.constraints) {
      this.validateRoleConstraints(role, userId);
    }

    // Проверка дублирования
    const existingAssignments = this.getRoleAssignmentsByUser(userId);
    const existingAssignment = existingAssignments.find(
      a => a.roleId === roleId && a.isActive
    );

    if (existingAssignment) {
      throw new AuthError(
        'Роль уже назначена пользователю',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        400
      );
    }

    const assignment: IRoleAssignment = {
      id: uuidv4(),
      userId,
      roleId,
      assignedBy,
      assignedAt: new Date(),
      expiresAt: options?.expiresAt,
      reason: options?.reason,
      isActive: true,
    };

    // Добавление в список назначений пользователя
    const userAssignments = this.roleAssignments.get(userId) || [];
    userAssignments.push(assignment);
    this.roleAssignments.set(userId, userAssignments);

    // Очистка кэша
    this.clearPermissionCache(userId);

    return assignment;
  }

  /**
   * Отменяет назначение роли
   * @param userId - ID пользователя
   * @param roleId - ID роли
   */
  public revokeRole(userId: string, roleId: string): void {
    const assignments = this.roleAssignments.get(userId) || [];
    const assignmentIndex = assignments.findIndex(
      a => a.roleId === roleId && a.isActive
    );

    if (assignmentIndex === -1) {
      throw new AuthError(
        'Роль не назначена пользователю',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        400
      );
    }

    assignments[assignmentIndex].isActive = false;
    this.roleAssignments.set(userId, assignments);

    // Очистка кэша
    this.clearPermissionCache(userId);
  }

  /**
   * Получает все назначения ролей пользователя
   * @param userId - ID пользователя
   * @returns Массив назначений
   */
  public getRoleAssignmentsByUser(userId: string): IRoleAssignment[] {
    return (this.roleAssignments.get(userId) || []).filter(a => {
      if (!a.isActive) return false;
      if (a.expiresAt && a.expiresAt < new Date()) return false;
      return true;
    });
  }

  /**
   * Получает все назначения для роли
   * @param roleId - ID роли
   * @returns Массив назначений
   */
  public getRoleAssignmentsByRole(roleId: string): IRoleAssignment[] {
    const result: IRoleAssignment[] = [];
    for (const assignments of this.roleAssignments.values()) {
      for (const assignment of assignments) {
        if (assignment.roleId === roleId && assignment.isActive) {
          result.push(assignment);
        }
      }
    }
    return result;
  }

  // ===========================================================================
  // ПРОВЕРКА РАЗРЕШЕНИЙ
  // ===========================================================================

  /**
   * Проверяет, имеет ли пользователь разрешение
   * @param user - Пользователь
   * @param permission - Разрешение (формат: resource:action[:scope])
   * @returns Результат проверки
   */
  public checkPermission(user: IUser, permission: string): AccessCheckResult {
    // Проверка кэша
    if (this.config.enableCaching) {
      const cached = this.getFromCache(user.id);
      if (cached && cached.has(permission)) {
        return { allowed: true };
      }
    }

    // Получение всех разрешений пользователя
    const userPermissions = this.getUserPermissions(user);

    // Проверка wildcard разрешений
    if (userPermissions.has('*:*:*')) {
      return { allowed: true };
    }

    // Проверка конкретного разрешения
    if (userPermissions.has(permission)) {
      return { allowed: true };
    }

    // Проверка wildcard по resource
    const [resource, action, scope] = permission.split(':');
    if (userPermissions.has(`${resource}:*`)) {
      return { allowed: true };
    }
    if (userPermissions.has(`${resource}:${action}`)) {
      return { allowed: true };
    }
    if (scope && userPermissions.has(`${resource}:${action}:*`)) {
      return { allowed: true };
    }

    return {
      allowed: false,
      denialReason: `Пользователь не имеет разрешения "${permission}"`,
    };
  }

  /**
   * Проверяет несколько разрешений одновременно
   * @param user - Пользователь
   * @param permissions - Список разрешений
   * @param requireAll - Требовать ли все разрешения (AND vs OR)
   * @returns Результат проверки
   */
  public checkPermissions(
    user: IUser,
    permissions: string[],
    requireAll: boolean = false
  ): AccessCheckResult {
    if (requireAll) {
      // Все разрешения должны быть (AND)
      for (const permission of permissions) {
        const result = this.checkPermission(user, permission);
        if (!result.allowed) {
          return result;
        }
      }
      return { allowed: true };
    } else {
      // Достаточно одного разрешения (OR)
      for (const permission of permissions) {
        const result = this.checkPermission(user, permission);
        if (result.allowed) {
          return { allowed: true };
        }
      }
      return {
        allowed: false,
        denialReason: 'Ни одно из разрешений не предоставлено',
      };
    }
  }

  /**
   * Получает все разрешения пользователя
   * @param user - Пользователь
   * @returns Set разрешений
   */
  public getUserPermissions(user: IUser): Set<string> {
    // Проверка кэша
    if (this.config.enableCaching) {
      const cached = this.getFromCache(user.id);
      if (cached) {
        return cached;
      }
    }

    const permissions = new Set<string>();

    // Получение активных ролей пользователя
    const assignments = this.getRoleAssignmentsByUser(user.id);
    const roleIds = assignments.map(a => a.roleId);

    // Добавление ролей из профиля пользователя
    for (const roleName of user.roles) {
      const role = this.getRoleByName(roleName);
      if (role && !roleIds.includes(role.id)) {
        roleIds.push(role.id);
      }
    }

    // Сбор разрешений из всех ролей
    for (const roleId of roleIds) {
      const rolePermissions = this.getRolePermissionsRecursive(roleId);
      for (const perm of rolePermissions) {
        permissions.add(perm);
      }
    }

    // Кэширование
    if (this.config.enableCaching) {
      this.addToCache(user.id, permissions);
    }

    return permissions;
  }

  /**
   * Получает разрешения роли с учетом иерархии
   * @private
   */
  private getRolePermissionsRecursive(
    roleId: string,
    visited: Set<string> = new Set()
  ): Set<string> {
    const permissions = new Set<string>();

    if (visited.has(roleId)) {
      return permissions; // Защита от циклических зависимостей
    }
    visited.add(roleId);

    const role = this.getRoleById(roleId);
    if (!role) {
      return permissions;
    }

    // Добавление разрешений роли
    for (const perm of role.permissions) {
      permissions.add(perm);
    }

    // Рекурсивное добавление разрешений родительских ролей
    if (this.config.enableRoleInheritance) {
      for (const parentRoleId of role.parentRoles) {
        const parentPermissions = this.getRolePermissionsRecursive(
          parentRoleId,
          visited
        );
        for (const perm of parentPermissions) {
          permissions.add(perm);
        }
      }
    }

    return permissions;
  }

  /**
   * Проверяет, имеет ли пользователь роль
   * @param user - Пользователь
   * @param roleName - Название роли
   * @returns Имеет ли роль
   */
  public hasRole(user: IUser, roleName: string): boolean {
    // Проверка прямых ролей
    if (user.roles.includes(roleName)) {
      return true;
    }

    // Проверка назначенных ролей
    const assignments = this.getRoleAssignmentsByUser(user.id);
    for (const assignment of assignments) {
      const role = this.getRoleById(assignment.roleId);
      if (role && role.name === roleName) {
        return true;
      }
    }

    return false;
  }

  /**
   * Проверяет, имеет ли пользователь любую из указанных ролей
   * @param user - Пользователь
   * @param roleNames - Список названий ролей
   * @returns Имеет ли хотя бы одну роль
   */
  public hasAnyRole(user: IUser, roleNames: string[]): boolean {
    return roleNames.some(name => this.hasRole(user, name));
  }

  /**
   * Проверяет, имеет ли пользователь все указанные роли
   * @param user - Пользователь
   * @param roleNames - Список названий ролей
   * @returns Имеет ли все роли
   */
  public hasAllRoles(user: IUser, roleNames: string[]): boolean {
    return roleNames.every(name => this.hasRole(user, name));
  }

  // ===========================================================================
  // ОГРАНИЧЕНИЯ РОЛЕЙ
  // ===========================================================================

  /**
   * Проверяет ограничения роли
   * @private
   */
  private validateRoleConstraints(role: IRole, userId: string): void {
    const constraints = role.constraints;

    // Проверка максимального количества пользователей
    if (constraints.maxUsers !== undefined) {
      const currentUsers = this.getRoleAssignmentsByRole(role.id).length;
      if (currentUsers >= constraints.maxUsers) {
        throw new AuthError(
          `Достигнут лимит пользователей для роли "${role.name}"`,
          AuthErrorCode.INSUFFICIENT_PERMISSIONS,
          400
        );
      }
    }

    // Проверка уровня clearance
    // В production реализовать проверку clearance уровня пользователя
  }

  // ===========================================================================
  // КЭШИРОВАНИЕ
  // ===========================================================================

  /**
   * Получает разрешения из кэша
   * @private
   */
  private getFromCache(userId: string): Set<string> | null {
    const cache = this.permissionCache.get(userId);
    if (!cache) return null;

    if (Date.now() > cache.expiresAt) {
      this.permissionCache.delete(userId);
      return null;
    }

    return cache.permissions;
  }

  /**
   * Добавляет разрешения в кэш
   * @private
   */
  private addToCache(userId: string, permissions: Set<string>): void {
    this.permissionCache.set(userId, {
      permissions,
      expiresAt: Date.now() + this.config.cacheTTL * 1000,
    });
  }

  /**
   * Очищает кэш для пользователя
   * @private
   */
  private clearPermissionCache(userId: string): void {
    this.permissionCache.delete(userId);
  }

  /**
   * Очищает кэш для всех пользователей с указанной ролью
   * @private
   */
  private clearPermissionCacheForRole(roleId: string): void {
    const assignments = this.getRoleAssignmentsByRole(roleId);
    for (const assignment of assignments) {
      this.clearPermissionCache(assignment.userId);
    }
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Парсит разрешение на компоненты
   * @param permission - Разрешение (resource:action:scope)
   * @returns Компоненты
   */
  public parsePermission(permission: string): {
    resource: string;
    action: string;
    scope?: string;
  } {
    const parts = permission.split(':');
    return {
      resource: parts[0] || '*',
      action: parts[1] || '*',
      scope: parts[2],
    };
  }

  /**
   * Создает разрешение из компонентов
   * @param resource - Ресурс
   * @param action - Действие
   * @param scope - Область (опционально)
   * @returns Разрешение
   */
  public createPermission(
    resource: string,
    action: string,
    scope?: string
  ): string {
    return scope ? `${resource}:${action}:${scope}` : `${resource}:${action}`;
  }

  /**
   * Получает статистику RBAC
   * @returns Статистика
   */
  public getStats(): {
    totalRoles: number;
    totalAssignments: number;
    systemRoles: number;
    customRoles: number;
  } {
    const roles = this.getAllRoles();
    const assignments = Array.from(this.roleAssignments.values()).flat();

    return {
      totalRoles: roles.length,
      totalAssignments: assignments.filter(a => a.isActive).length,
      systemRoles: roles.filter(r => r.isSystem).length,
      customRoles: roles.filter(r => !r.isSystem).length,
    };
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const rbacService = new RBACService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createRBACService(
  config: Partial<RBACServiceConfig>
): RBACService {
  return new RBACService({ ...DEFAULT_CONFIG, ...config });
}
