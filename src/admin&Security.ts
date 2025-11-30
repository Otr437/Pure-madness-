// ============================================================================
// X402 ADMIN & SECURITY MODULE - COMPLETE PRODUCTION IMPLEMENTATION
// ============================================================================
// Component 7 of 8
// Rate limiting, admin controls, 2FA, audit logging, emergency systems
// Complete security infrastructure for production deployment
// ============================================================================

import {
  Field,
  PublicKey,
  Signature,
  Bool,
  UInt64,
  UInt32,
  Poseidon,
  Struct,
} from 'o1js';

// ============================================================================
// RATE LIMITER
// ============================================================================

export class RateLimiter {
  private requests: Map<string, number[]>;
  private windowMs: number;
  private maxRequests: number;

  constructor(windowMs: number = 900000, maxRequests: number = 100) {
    this.requests = new Map();
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  checkLimit(identifier: string): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  } {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    const userRequests = this.requests.get(identifier) || [];
    const validRequests = userRequests.filter(timestamp => timestamp > windowStart);

    if (validRequests.length >= this.maxRequests) {
      const oldestRequest = Math.min(...validRequests);
      const resetTime = oldestRequest + this.windowMs;

      return {
        allowed: false,
        remaining: 0,
        resetTime,
      };
    }

    validRequests.push(now);
    this.requests.set(identifier, validRequests);

    return {
      allowed: true,
      remaining: this.maxRequests - validRequests.length,
      resetTime: now + this.windowMs,
    };
  }

  reset(identifier: string): void {
    this.requests.delete(identifier);
  }

  clear(): void {
    this.requests.clear();
  }

  cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    this.requests.forEach((timestamps, identifier) => {
      const validRequests = timestamps.filter(t => t > windowStart);
      if (validRequests.length === 0) {
        this.requests.delete(identifier);
      } else {
        this.requests.set(identifier, validRequests);
      }
    });
  }

  getStatistics(): {
    totalUsers: number;
    totalRequests: number;
    averageRequestsPerUser: number;
  } {
    let totalRequests = 0;
    
    this.requests.forEach(timestamps => {
      totalRequests += timestamps.length;
    });

    const totalUsers = this.requests.size;
    const averageRequestsPerUser = totalUsers === 0 ? 0 : totalRequests / totalUsers;

    return {
      totalUsers,
      totalRequests,
      averageRequestsPerUser,
    };
  }
}

// ============================================================================
// ADMIN RATE LIMITER (SEPARATE HIGHER LIMITS)
// ============================================================================

export class AdminRateLimiter extends RateLimiter {
  constructor() {
    super(900000, 200);
  }
}

// ============================================================================
// TWO-FACTOR AUTHENTICATION
// ============================================================================

export class TwoFactorAuth {
  private secrets: Map<string, string>;
  private backupCodes: Map<string, Set<string>>;
  private verifiedSessions: Map<string, number>;
  private sessionDuration: number;

  constructor(sessionDuration: number = 3600000) {
    this.secrets = new Map();
    this.backupCodes = new Map();
    this.verifiedSessions = new Map();
    this.sessionDuration = sessionDuration;
  }

  generateSecret(identifier: string): string {
    const secret = this.generateRandomBase32(32);
    this.secrets.set(identifier, secret);
    return secret;
  }

  generateBackupCodes(identifier: string, count: number = 10): string[] {
    const codes: string[] = [];
    const codeSet = new Set<string>();

    for (let i = 0; i < count; i++) {
      const code = this.generateRandomCode(8);
      codes.push(code);
      codeSet.add(code);
    }

    this.backupCodes.set(identifier, codeSet);
    return codes;
  }

  verifyTOTP(identifier: string, token: string): boolean {
    const secret = this.secrets.get(identifier);
    if (!secret) return false;

    const currentTime = Math.floor(Date.now() / 1000);
    const timeStep = 30;
    const window = 1;

    for (let i = -window; i <= window; i++) {
      const timeCounter = Math.floor(currentTime / timeStep) + i;
      const expectedToken = this.generateTOTP(secret, timeCounter);
      
      if (token === expectedToken) {
        this.verifiedSessions.set(identifier, Date.now() + this.sessionDuration);
        return true;
      }
    }

    return false;
  }

  verifyBackupCode(identifier: string, code: string): boolean {
    const codes = this.backupCodes.get(identifier);
    if (!codes || !codes.has(code)) return false;

    codes.delete(code);
    this.verifiedSessions.set(identifier, Date.now() + this.sessionDuration);
    return true;
  }

  isSessionValid(identifier: string): boolean {
    const expiryTime = this.verifiedSessions.get(identifier);
    if (!expiryTime) return false;

    if (Date.now() > expiryTime) {
      this.verifiedSessions.delete(identifier);
      return false;
    }

    return true;
  }

  revokeSession(identifier: string): void {
    this.verifiedSessions.delete(identifier);
  }

  disable(identifier: string): void {
    this.secrets.delete(identifier);
    this.backupCodes.delete(identifier);
    this.verifiedSessions.delete(identifier);
  }

  private generateTOTP(secret: string, timeCounter: number): string {
    const buffer = Buffer.alloc(8);
    buffer.writeBigInt64BE(BigInt(timeCounter));
    
    const hash = this.hmacSHA1(this.base32Decode(secret), buffer);
    const offset = hash[hash.length - 1] & 0x0f;
    
    const code = (
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff)
    ) % 1000000;

    return code.toString().padStart(6, '0');
  }

  private hmacSHA1(key: Buffer, message: Buffer): Buffer {
    const crypto = require('crypto');
    return crypto.createHmac('sha1', key).update(message).digest();
  }

  private base32Decode(encoded: string): Buffer {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bits: number[] = [];

    for (const char of encoded.toUpperCase()) {
      const val = alphabet.indexOf(char);
      if (val === -1) continue;
      bits.push(...val.toString(2).padStart(5, '0').split('').map(Number));
    }

    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8).join(''), 2));
    }

    return Buffer.from(bytes);
  }

  private generateRandomBase32(length: number): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    const crypto = require('crypto');
    const bytes = crypto.randomBytes(length);

    for (let i = 0; i < length; i++) {
      result += alphabet[bytes[i] % 32];
    }

    return result;
  }

  private generateRandomCode(length: number): string {
    const crypto = require('crypto');
    const bytes = crypto.randomBytes(length);
    return bytes.toString('hex').substring(0, length).toUpperCase();
  }
}

// ============================================================================
// ADMIN ACTION LOG
// ============================================================================

export class AdminActionLog extends Struct({
  actionId: Field,
  admin: PublicKey,
  action: Field,
  target: Field,
  timestamp: UInt64,
  parameters: Field,
  signature: Signature,
}) {
  static ACTION_PAUSE = Field(1);
  static ACTION_UNPAUSE = Field(2);
  static ACTION_UPDATE_FEE = Field(3);
  static ACTION_TRANSFER_OWNERSHIP = Field(4);
  static ACTION_CANCEL_GAME = Field(5);
  static ACTION_SUSPEND_USER = Field(6);
  static ACTION_UPDATE_LIMITS = Field(7);

  toJSON(): {
    actionId: string;
    admin: string;
    action: string;
    target: string;
    timestamp: string;
    parameters: string;
    signature: { r: string; s: string };
  } {
    return {
      actionId: this.actionId.toString(),
      admin: this.admin.toBase58(),
      action: this.action.toString(),
      target: this.target.toString(),
      timestamp: this.timestamp.toString(),
      parameters: this.parameters.toString(),
      signature: {
        r: this.signature.r.toString(),
        s: this.signature.s.toString(),
      },
    };
  }
}

// ============================================================================
// ADMIN ACTION LOGGER
// ============================================================================

export class AdminActionLogger {
  private logs: AdminActionLog[];
  private logsByAdmin: Map<string, AdminActionLog[]>;
  private logsByAction: Map<string, AdminActionLog[]>;

  constructor() {
    this.logs = [];
    this.logsByAdmin = new Map();
    this.logsByAction = new Map();
  }

  log(actionLog: AdminActionLog): void {
    this.logs.push(actionLog);

    const adminKey = actionLog.admin.toBase58();
    if (!this.logsByAdmin.has(adminKey)) {
      this.logsByAdmin.set(adminKey, []);
    }
    this.logsByAdmin.get(adminKey)!.push(actionLog);

    const actionKey = actionLog.action.toString();
    if (!this.logsByAction.has(actionKey)) {
      this.logsByAction.set(actionKey, []);
    }
    this.logsByAction.get(actionKey)!.push(actionLog);
  }

  getByAdmin(admin: PublicKey): AdminActionLog[] {
    return this.logsByAdmin.get(admin.toBase58()) || [];
  }

  getByAction(action: Field): AdminActionLog[] {
    return this.logsByAction.get(action.toString()) || [];
  }

  getByTimeRange(startTime: bigint, endTime: bigint): AdminActionLog[] {
    return this.logs.filter(log => {
      const timestamp = log.timestamp.value.toBigInt();
      return timestamp >= startTime && timestamp <= endTime;
    });
  }

  getAll(): AdminActionLog[] {
    return [...this.logs];
  }

  exportToJSON(): string {
    return JSON.stringify(this.logs.map(log => log.toJSON()), null, 2);
  }

  async saveToFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const json = this.exportToJSON();
    await fs.writeFile(filepath, json, 'utf8');
  }

  getStatistics(): {
    totalActions: number;
    actionsByType: Record<string, number>;
    actionsByAdmin: Record<string, number>;
    recentActions: number;
  } {
    const stats = {
      totalActions: this.logs.length,
      actionsByType: {} as Record<string, number>,
      actionsByAdmin: {} as Record<string, number>,
      recentActions: 0,
    };

    const oneDayAgo = BigInt(Math.floor(Date.now() / 1000)) - 86400n;

    this.logs.forEach(log => {
      const actionType = log.action.toString();
      stats.actionsByType[actionType] = (stats.actionsByType[actionType] || 0) + 1;

      const adminKey = log.admin.toBase58();
      stats.actionsByAdmin[adminKey] = (stats.actionsByAdmin[adminKey] || 0) + 1;

      if (log.timestamp.value.toBigInt() >= oneDayAgo) {
        stats.recentActions++;
      }
    });

    return stats;
  }
}

// ============================================================================
// SUSPENDED USERS MANAGER
// ============================================================================

export class SuspendedUsersManager {
  private suspendedUsers: Map<string, {
    publicKey: PublicKey;
    reason: string;
    suspendedAt: bigint;
    suspendedBy: PublicKey;
    expiresAt: bigint | null;
  }>;

  constructor() {
    this.suspendedUsers = new Map();
  }

  suspend(
    userPublicKey: PublicKey,
    reason: string,
    suspendedBy: PublicKey,
    durationSeconds?: bigint
  ): void {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const expiresAt = durationSeconds ? now + durationSeconds : null;

    this.suspendedUsers.set(userPublicKey.toBase58(), {
      publicKey: userPublicKey,
      reason,
      suspendedAt: now,
      suspendedBy,
      expiresAt,
    });
  }

  unsuspend(userPublicKey: PublicKey): boolean {
    return this.suspendedUsers.delete(userPublicKey.toBase58());
  }

  isSuspended(userPublicKey: PublicKey): boolean {
    const suspension = this.suspendedUsers.get(userPublicKey.toBase58());
    if (!suspension) return false;

    if (suspension.expiresAt) {
      const now = BigInt(Math.floor(Date.now() / 1000));
      if (now >= suspension.expiresAt) {
        this.suspendedUsers.delete(userPublicKey.toBase58());
        return false;
      }
    }

    return true;
  }

  getSuspensionInfo(userPublicKey: PublicKey): {
    reason: string;
    suspendedAt: bigint;
    suspendedBy: string;
    expiresAt: bigint | null;
  } | null {
    const suspension = this.suspendedUsers.get(userPublicKey.toBase58());
    if (!suspension) return null;

    return {
      reason: suspension.reason,
      suspendedAt: suspension.suspendedAt,
      suspendedBy: suspension.suspendedBy.toBase58(),
      expiresAt: suspension.expiresAt,
    };
  }

  getAll(): Array<{
    publicKey: string;
    reason: string;
    suspendedAt: bigint;
    suspendedBy: string;
    expiresAt: bigint | null;
  }> {
    return Array.from(this.suspendedUsers.values()).map(s => ({
      publicKey: s.publicKey.toBase58(),
      reason: s.reason,
      suspendedAt: s.suspendedAt,
      suspendedBy: s.suspendedBy.toBase58(),
      expiresAt: s.expiresAt,
    }));
  }

  cleanupExpired(): number {
    const now = BigInt(Math.floor(Date.now() / 1000));
    let cleaned = 0;

    this.suspendedUsers.forEach((suspension, key) => {
      if (suspension.expiresAt && now >= suspension.expiresAt) {
        this.suspendedUsers.delete(key);
        cleaned++;
      }
    });

    return cleaned;
  }
}

// ============================================================================
// EMERGENCY PAUSE MANAGER
// ============================================================================

export class EmergencyPauseManager {
  private isPaused: boolean;
  private pauseReason: string;
  private pausedAt: bigint;
  private pausedBy: PublicKey | null;
  private pauseHistory: Array<{
    paused: boolean;
    reason: string;
    timestamp: bigint;
    admin: PublicKey;
  }>;

  constructor() {
    this.isPaused = false;
    this.pauseReason = '';
    this.pausedAt = 0n;
    this.pausedBy = null;
    this.pauseHistory = [];
  }

  pause(reason: string, admin: PublicKey): void {
    this.isPaused = true;
    this.pauseReason = reason;
    this.pausedAt = BigInt(Math.floor(Date.now() / 1000));
    this.pausedBy = admin;

    this.pauseHistory.push({
      paused: true,
      reason,
      timestamp: this.pausedAt,
      admin,
    });
  }

  unpause(admin: PublicKey): void {
    this.isPaused = false;
    const timestamp = BigInt(Math.floor(Date.now() / 1000));

    this.pauseHistory.push({
      paused: false,
      reason: 'System resumed',
      timestamp,
      admin,
    });
  }

  getPauseStatus(): {
    isPaused: boolean;
    reason: string;
    pausedAt: bigint;
    pausedBy: string | null;
    duration: bigint;
  } {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const duration = this.isPaused ? now - this.pausedAt : 0n;

    return {
      isPaused: this.isPaused,
      reason: this.pauseReason,
      pausedAt: this.pausedAt,
      pausedBy: this.pausedBy?.toBase58() || null,
      duration,
    };
  }

  getPauseHistory(): Array<{
    paused: boolean;
    reason: string;
    timestamp: bigint;
    admin: string;
  }> {
    return this.pauseHistory.map(entry => ({
      paused: entry.paused,
      reason: entry.reason,
      timestamp: entry.timestamp,
      admin: entry.admin.toBase58(),
    }));
  }
}

// ============================================================================
// SECURITY MONITOR
// ============================================================================

export class SecurityMonitor {
  private suspiciousActivities: Array<{
    identifier: string;
    activity: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    timestamp: bigint;
    details: string;
  }>;

  constructor() {
    this.suspiciousActivities = [];
  }

  reportActivity(
    identifier: string,
    activity: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    details: string
  ): void {
    this.suspiciousActivities.push({
      identifier,
      activity,
      severity,
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
      details,
    });

    if (severity === 'critical') {
      console.error(`CRITICAL SECURITY EVENT: ${activity} - ${details}`);
    }
  }

  getActivitiesBySeverity(severity: 'low' | 'medium' | 'high' | 'critical'): Array<{
    identifier: string;
    activity: string;
    timestamp: bigint;
    details: string;
  }> {
    return this.suspiciousActivities
      .filter(a => a.severity === severity)
      .map(({ identifier, activity, timestamp, details }) => ({
        identifier,
        activity,
        timestamp,
        details,
      }));
  }

  getActivitiesByIdentifier(identifier: string): Array<{
    activity: string;
    severity: string;
    timestamp: bigint;
    details: string;
  }> {
    return this.suspiciousActivities
      .filter(a => a.identifier === identifier)
      .map(({ activity, severity, timestamp, details }) => ({
        activity,
        severity,
        timestamp,
        details,
      }));
  }

  getRecentActivities(hours: number = 24): Array<{
    identifier: string;
    activity: string;
    severity: string;
    timestamp: bigint;
    details: string;
  }> {
    const cutoff = BigInt(Math.floor(Date.now() / 1000)) - BigInt(hours * 3600);
    return this.suspiciousActivities
      .filter(a => a.timestamp >= cutoff)
      .map(({ identifier, activity, severity, timestamp, details }) => ({
        identifier,
        activity,
        severity,
        timestamp,
        details,
      }));
  }

  clearOldActivities(daysToKeep: number = 30): number {
    const cutoff = BigInt(Math.floor(Date.now() / 1000)) - BigInt(daysToKeep * 86400);
    const originalLength = this.suspiciousActivities.length;
    
    this.suspiciousActivities = this.suspiciousActivities.filter(
      a => a.timestamp >= cutoff
    );

    return originalLength - this.suspiciousActivities.length;
  }

  getStatistics(): {
    total: number;
    bySeverity: Record<string, number>;
    recentCritical: number;
  } {
    const stats = {
      total: this.suspiciousActivities.length,
      bySeverity: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
      recentCritical: 0,
    };

    const oneDayAgo = BigInt(Math.floor(Date.now() / 1000)) - 86400n;

    this.suspiciousActivities.forEach(activity => {
      stats.bySeverity[activity.severity]++;
      
      if (activity.severity === 'critical' && activity.timestamp >= oneDayAgo) {
        stats.recentCritical++;
      }
    });

    return stats;
  }
}

// ============================================================================
// COMPLETE SECURITY MANAGER
// ============================================================================

export class SecurityManager {
  public rateLimiter: RateLimiter;
  public adminRateLimiter: AdminRateLimiter;
  public twoFactorAuth: TwoFactorAuth;
  public actionLogger: AdminActionLogger;
  public suspendedUsers: SuspendedUsersManager;
  public emergencyPause: EmergencyPauseManager;
  public securityMonitor: SecurityMonitor;

  constructor() {
    this.rateLimiter = new RateLimiter();
    this.adminRateLimiter = new AdminRateLimiter();
    this.twoFactorAuth = new TwoFactorAuth();
    this.actionLogger = new AdminActionLogger();
    this.suspendedUsers = new SuspendedUsersManager();
    this.emergencyPause = new EmergencyPauseManager();
    this.securityMonitor = new SecurityMonitor();
  }

  checkUserAccess(userPublicKey: PublicKey, identifier: string): {
    allowed: boolean;
    reason?: string;
  } {
    if (this.emergencyPause.getPauseStatus().isPaused) {
      return { allowed: false, reason: 'System is paused' };
    }

    if (this.suspendedUsers.isSuspended(userPublicKey)) {
      return { allowed: false, reason: 'User is suspended' };
    }

    const rateLimit = this.rateLimiter.checkLimit(identifier);
    if (!rateLimit.allowed) {
      return { allowed: false, reason: 'Rate limit exceeded' };
    }

    return { allowed: true };
  }

  checkAdminAccess(adminPublicKey: PublicKey, identifier: string, requiresTwoFactor: boolean): {
    allowed: boolean;
    reason?: string;
  } {
    if (requiresTwoFactor && !this.twoFactorAuth.isSessionValid(identifier)) {
      return { allowed: false, reason: '2FA required' };
    }

    const rateLimit = this.adminRateLimiter.checkLimit(identifier);
    if (!rateLimit.allowed) {
      return { allowed: false, reason: 'Admin rate limit exceeded' };
    }

    return { allowed: true };
  }

  getCompleteStatus(): {
    isPaused: boolean;
    suspendedUsersCount: number;
    totalAdminActions: number;
    recentSecurityEvents: number;
    rateLimitStats: any;
  } {
    return {
      isPaused: this.emergencyPause.getPauseStatus().isPaused,
      suspendedUsersCount: this.suspendedUsers.getAll().length,
      totalAdminActions: this.actionLogger.getAll().length,
      recentSecurityEvents: this.securityMonitor.getRecentActivities(24).length,
      rateLimitStats: this.rateLimiter.getStatistics(),
    };
  }
}