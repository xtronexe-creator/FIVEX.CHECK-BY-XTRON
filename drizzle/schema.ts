import { pgTable, serial, text, varchar, timestamp, integer, boolean, pgEnum, jsonb } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// Enums
export const roleEnum = pgEnum('role', ['user', 'admin']);
export const statusEnum = pgEnum('status', ['active', 'used', 'expired']);
export const scanStatusEnum = pgEnum('scan_status', ['in_progress', 'completed', 'failed']);
export const riskLevelEnum = pgEnum('risk_level', ['suspicious', 'warning', 'moderate', 'safe']);
export const logLevelEnum = pgEnum('log_level', ['INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG']);

// Users table
export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  openId: varchar('open_id', { length: 64 }).notNull().unique(),
  name: text('name'),
  email: varchar('email', { length: 320 }),
  loginMethod: varchar('login_method', { length: 64 }),
  role: roleEnum('role').notNull().default('user'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  lastSignedIn: timestamp('last_signed_in').notNull().defaultNow(),
});

// Scan codes table
export const scanCodes = pgTable('scan_codes', {
  id: serial('id').primaryKey(),
  code: varchar('code', { length: 12 }).notNull().unique(),
  status: statusEnum('status').notNull().default('active'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
  usedByDevice: varchar('used_by_device', { length: 255 }),
  createdByUserId: integer('created_by_user_id').references(() => users.id),
});

// Scan results table (with systemInfo field)
export const scanResults = pgTable('scan_results', {
  id: serial('id').primaryKey(),
  scanCodeId: integer('scan_code_id').references(() => scanCodes.id),
  deviceName: varchar('device_name', { length: 255 }).notNull(),
  osVersion: varchar('os_version', { length: 255 }),
  systemInfo: jsonb('system_info'), // New field for system details
  scanStartTime: timestamp('scan_start_time').notNull().defaultNow(),
  scanEndTime: timestamp('scan_end_time'),
  totalFilesScanned: integer('total_files_scanned').default(0),
  suspiciousCount: integer('suspicious_count').default(0),
  warningCount: integer('warning_count').default(0),
  moderateCount: integer('moderate_count').default(0),
  safeCount: integer('safe_count').default(0),
  overallRiskLevel: riskLevelEnum('overall_risk_level'),
  scanStatus: scanStatusEnum('scan_status').notNull().default('in_progress'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// Scan files table
export const scanFiles = pgTable('scan_files', {
  id: serial('id').primaryKey(),
  scanResultId: integer('scan_result_id').references(() => scanResults.id),
  filePath: text('file_path').notNull(),
  fileName: varchar('file_name', { length: 255 }).notNull(),
  fileType: varchar('file_type', { length: 50 }),
  fileSize: integer('file_size'),
  riskLevel: riskLevelEnum('risk_level').notNull(),
  detectionReason: text('detection_reason'),
  fileHash: varchar('file_hash', { length: 64 }),
  createdDate: timestamp('created_date'),
  modifiedDate: timestamp('modified_date'),
  isFiveMMod: boolean('is_fivem_mod').default(false),
  isSystemFile: boolean('is_system_file').default(false),
  windowsDetails: text('windows_details'),
});

// Scan logs table
export const scanLogs = pgTable('scan_logs', {
  id: serial('id').primaryKey(),
  scanResultId: integer('scan_result_id').references(() => scanResults.id),
  logLevel: logLevelEnum('log_level').notNull(),
  message: text('message').notNull(),
  filePath: text('file_path'),
  progress: integer('progress'),
  metadata: text('metadata'),
  timestamp: timestamp('timestamp').notNull().defaultNow(),
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  scanCodes: many(scanCodes),
}));

export const scanCodesRelations = relations(scanCodes, ({ one, many }) => ({
  createdBy: one(users, {
    fields: [scanCodes.createdByUserId],
    references: [users.id],
  }),
  scanResults: many(scanResults),
}));

export const scanResultsRelations = relations(scanResults, ({ one, many }) => ({
  scanCode: one(scanCodes, {
    fields: [scanResults.scanCodeId],
    references: [scanCodes.id],
  }),
  files: many(scanFiles),
  logs: many(scanLogs),
}));

export const scanFilesRelations = relations(scanFiles, ({ one }) => ({
  scanResult: one(scanResults, {
    fields: [scanFiles.scanResultId],
    references: [scanResults.id],
  }),
}));

export const scanLogsRelations = relations(scanLogs, ({ one }) => ({
  scanResult: one(scanResults, {
    fields: [scanLogs.scanResultId],
    references: [scanResults.id],
  }),
}));

// Insert Types
export type InsertUser = typeof users.$inferInsert;
export type InsertScanCode = typeof scanCodes.$inferInsert;
export type InsertScanResult = typeof scanResults.$inferInsert;
export type InsertScanFile = typeof scanFiles.$inferInsert;
export type InsertScanLog = typeof scanLogs.$inferInsert;

// Select Types (optional)
export type SelectUser = typeof users.$inferSelect;
export type SelectScanCode = typeof scanCodes.$inferSelect;
export type SelectScanResult = typeof scanResults.$inferSelect;
export type SelectScanFile = typeof scanFiles.$inferSelect;
export type SelectScanLog = typeof scanLogs.$inferSelect;