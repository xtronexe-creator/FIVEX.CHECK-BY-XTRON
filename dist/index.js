var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/_core/index.ts
import "dotenv/config";
import cookieParser from "cookie-parser";
import express2 from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";

// shared/const.ts
var COOKIE_NAME = "app_session_id";
var ONE_YEAR_MS = 1e3 * 60 * 60 * 24 * 365;
var UNAUTHED_ERR_MSG = "Please login (10001)";
var NOT_ADMIN_ERR_MSG = "You do not have required permission (10002)";

// server/db.ts
import { eq, desc, lt, and } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { sql } from "drizzle-orm";

// drizzle/schema.ts
var schema_exports = {};
__export(schema_exports, {
  logLevelEnum: () => logLevelEnum,
  riskLevelEnum: () => riskLevelEnum,
  roleEnum: () => roleEnum,
  scanCodes: () => scanCodes,
  scanCodesRelations: () => scanCodesRelations,
  scanFiles: () => scanFiles,
  scanFilesRelations: () => scanFilesRelations,
  scanLogs: () => scanLogs,
  scanLogsRelations: () => scanLogsRelations,
  scanResults: () => scanResults,
  scanResultsRelations: () => scanResultsRelations,
  scanStatusEnum: () => scanStatusEnum,
  statusEnum: () => statusEnum,
  users: () => users,
  usersRelations: () => usersRelations
});
import { pgTable, serial, text, varchar, timestamp, integer, boolean, pgEnum, jsonb } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
var roleEnum = pgEnum("role", ["user", "admin"]);
var statusEnum = pgEnum("status", ["active", "used", "expired"]);
var scanStatusEnum = pgEnum("scan_status", ["in_progress", "completed", "failed"]);
var riskLevelEnum = pgEnum("risk_level", ["suspicious", "warning", "moderate", "safe"]);
var logLevelEnum = pgEnum("log_level", ["INFO", "SUCCESS", "WARN", "ERROR", "DEBUG"]);
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  openId: varchar("open_id", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("login_method", { length: 64 }),
  role: roleEnum("role").notNull().default("user"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  lastSignedIn: timestamp("last_signed_in").notNull().defaultNow()
});
var scanCodes = pgTable("scan_codes", {
  id: serial("id").primaryKey(),
  code: varchar("code", { length: 12 }).notNull().unique(),
  status: statusEnum("status").notNull().default("active"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  expiresAt: timestamp("expires_at").notNull(),
  usedAt: timestamp("used_at"),
  usedByDevice: varchar("used_by_device", { length: 255 }),
  createdByUserId: integer("created_by_user_id").references(() => users.id)
});
var scanResults = pgTable("scan_results", {
  id: serial("id").primaryKey(),
  scanCodeId: integer("scan_code_id").references(() => scanCodes.id),
  deviceName: varchar("device_name", { length: 255 }).notNull(),
  osVersion: varchar("os_version", { length: 255 }),
  systemInfo: jsonb("system_info"),
  // New field for system details
  scanStartTime: timestamp("scan_start_time").notNull().defaultNow(),
  scanEndTime: timestamp("scan_end_time"),
  totalFilesScanned: integer("total_files_scanned").default(0),
  suspiciousCount: integer("suspicious_count").default(0),
  warningCount: integer("warning_count").default(0),
  moderateCount: integer("moderate_count").default(0),
  safeCount: integer("safe_count").default(0),
  overallRiskLevel: riskLevelEnum("overall_risk_level"),
  scanStatus: scanStatusEnum("scan_status").notNull().default("in_progress"),
  createdAt: timestamp("created_at").notNull().defaultNow()
});
var scanFiles = pgTable("scan_files", {
  id: serial("id").primaryKey(),
  scanResultId: integer("scan_result_id").references(() => scanResults.id),
  filePath: text("file_path").notNull(),
  fileName: varchar("file_name", { length: 255 }).notNull(),
  fileType: varchar("file_type", { length: 50 }),
  fileSize: integer("file_size"),
  riskLevel: riskLevelEnum("risk_level").notNull(),
  detectionReason: text("detection_reason"),
  fileHash: varchar("file_hash", { length: 64 }),
  createdDate: timestamp("created_date"),
  modifiedDate: timestamp("modified_date"),
  isFiveMMod: boolean("is_fivem_mod").default(false),
  isSystemFile: boolean("is_system_file").default(false),
  windowsDetails: text("windows_details")
});
var scanLogs = pgTable("scan_logs", {
  id: serial("id").primaryKey(),
  scanResultId: integer("scan_result_id").references(() => scanResults.id),
  logLevel: logLevelEnum("log_level").notNull(),
  message: text("message").notNull(),
  filePath: text("file_path"),
  progress: integer("progress"),
  metadata: text("metadata"),
  timestamp: timestamp("timestamp").notNull().defaultNow()
});
var usersRelations = relations(users, ({ many }) => ({
  scanCodes: many(scanCodes)
}));
var scanCodesRelations = relations(scanCodes, ({ one, many }) => ({
  createdBy: one(users, {
    fields: [scanCodes.createdByUserId],
    references: [users.id]
  }),
  scanResults: many(scanResults)
}));
var scanResultsRelations = relations(scanResults, ({ one, many }) => ({
  scanCode: one(scanCodes, {
    fields: [scanResults.scanCodeId],
    references: [scanCodes.id]
  }),
  files: many(scanFiles),
  logs: many(scanLogs)
}));
var scanFilesRelations = relations(scanFiles, ({ one }) => ({
  scanResult: one(scanResults, {
    fields: [scanFiles.scanResultId],
    references: [scanResults.id]
  })
}));
var scanLogsRelations = relations(scanLogs, ({ one }) => ({
  scanResult: one(scanResults, {
    fields: [scanLogs.scanResultId],
    references: [scanResults.id]
  })
}));

// server/_core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? ""
};

// server/db.ts
var _db = null;
var _pool = null;
async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _pool = new Pool({ connectionString: process.env.DATABASE_URL });
      _db = drizzle(_pool, { schema: schema_exports });
      console.log("\u2705 Database connected successfully");
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}
async function upsertUser(user) {
  if (!user.openId) throw new Error("User openId is required");
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values = { openId: user.openId };
    if (user.name !== void 0) values.name = user.name;
    if (user.email !== void 0) values.email = user.email;
    if (user.loginMethod !== void 0) values.loginMethod = user.loginMethod;
    if (user.role !== void 0) {
      values.role = user.role;
    } else if (user.openId === "admin-user" || user.openId === ENV.ownerOpenId) {
      values.role = "admin";
    } else {
      values.role = "user";
    }
    values.lastSignedIn = user.lastSignedIn || /* @__PURE__ */ new Date();
    values.createdAt = /* @__PURE__ */ new Date();
    values.updatedAt = /* @__PURE__ */ new Date();
    await db.insert(users).values(values).onConflictDoUpdate({
      target: users.openId,
      set: {
        name: values.name,
        email: values.email,
        loginMethod: values.loginMethod,
        role: values.role,
        lastSignedIn: values.lastSignedIn,
        updatedAt: /* @__PURE__ */ new Date()
      }
    });
    console.log(`\u2705 User upserted: ${values.openId} (${values.role})`);
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result[0];
}
async function generateScanCode(userId, expirationHours = 24) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const code = generateRandomCode();
  const expiresAt = new Date(Date.now() + expirationHours * 60 * 60 * 1e3);
  await db.insert(scanCodes).values({
    code,
    createdByUserId: userId,
    expiresAt,
    status: "active"
  });
  return code;
}
async function validateAndUseScanCode(code, deviceName) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(scanCodes).where(eq(scanCodes.code, code)).limit(1);
  if (!result.length) return { valid: false };
  const codeRecord = result[0];
  if (codeRecord.status !== "active" || /* @__PURE__ */ new Date() > codeRecord.expiresAt) {
    return { valid: false };
  }
  await db.update(scanCodes).set({
    status: "used",
    usedAt: /* @__PURE__ */ new Date(),
    usedByDevice: deviceName
  }).where(eq(scanCodes.code, code));
  return { valid: true, codeId: codeRecord.id };
}
async function getAllScanCodes() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(scanCodes).orderBy(desc(scanCodes.createdAt));
}
async function deleteScanCode(codeId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.delete(scanCodes).where(eq(scanCodes.id, codeId));
}
async function createScanResult(data) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  try {
    const [result] = await db.insert(scanResults).values(data).returning();
    return result;
  } catch (error) {
    console.error("\u274C Database error in createScanResult:", error);
    throw new Error(`Failed to create scan result: ${error instanceof Error ? error.message : String(error)}`);
  }
}
async function getAllScanResults() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(scanResults).orderBy(desc(scanResults.createdAt));
}
async function getScanResultWithFiles(scanResultId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const [result] = await db.select().from(scanResults).where(eq(scanResults.id, scanResultId)).limit(1);
  if (!result) return null;
  const files = await db.select().from(scanFiles).where(eq(scanFiles.scanResultId, scanResultId));
  let scanKey = null;
  if (result.scanCodeId) {
    const [codeRow] = await db.select({ code: scanCodes.code }).from(scanCodes).where(eq(scanCodes.id, result.scanCodeId)).limit(1);
    scanKey = codeRow?.code ?? null;
  }
  console.log(`[getScanResultWithFiles] Found ${files.length} files for scanResultId ${scanResultId}`);
  return { ...result, scanKey, files };
}
async function addScanFiles(scanResultId, files) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  if (files.length === 0) return;
  const filesWithId = files.map((f) => ({ ...f, scanResultId }));
  console.log(`[addScanFiles] Inserting ${filesWithId.length} files for scanResultId: ${scanResultId}`);
  try {
    await db.insert(scanFiles).values(filesWithId);
    console.log(`[addScanFiles] Success`);
    await updateScanResultCounts(scanResultId);
  } catch (error) {
    console.error("[addScanFiles] Error:", error);
    throw error;
  }
}
async function updateScanResultCounts(scanResultId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const counts = await db.select({
    riskLevel: scanFiles.riskLevel,
    count: sql`count(*)`
  }).from(scanFiles).where(eq(scanFiles.scanResultId, scanResultId)).groupBy(scanFiles.riskLevel);
  const suspiciousCount = counts.find((c) => c.riskLevel === "suspicious")?.count || 0;
  const warningCount = counts.find((c) => c.riskLevel === "warning")?.count || 0;
  const moderateCount = counts.find((c) => c.riskLevel === "moderate")?.count || 0;
  const safeCount = counts.find((c) => c.riskLevel === "safe")?.count || 0;
  const total = suspiciousCount + warningCount + moderateCount + safeCount;
  await db.update(scanResults).set({
    totalFilesScanned: total,
    suspiciousCount,
    warningCount,
    moderateCount,
    safeCount
  }).where(eq(scanResults.id, scanResultId));
  console.log(`[updateScanResultCounts] Updated counts for scanResult ${scanResultId}: total=${total}, sus=${suspiciousCount}, warn=${warningCount}, mod=${moderateCount}, safe=${safeCount}`);
}
async function updateScanResultStatus(scanResultId, status, endTime, overallRiskLevel) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const updateData = { scanStatus: status };
  if (endTime) updateData.scanEndTime = endTime;
  if (overallRiskLevel) updateData.overallRiskLevel = overallRiskLevel;
  await db.update(scanResults).set(updateData).where(eq(scanResults.id, scanResultId));
}
async function setScanResultCounts(scanResultId, counts) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.update(scanResults).set({
    totalFilesScanned: counts.totalFilesScanned,
    suspiciousCount: counts.suspiciousCount,
    warningCount: counts.warningCount,
    moderateCount: counts.moderateCount,
    safeCount: counts.safeCount
  }).where(eq(scanResults.id, scanResultId));
}
async function addScanLog(log) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.insert(scanLogs).values(log);
}
async function getRecentScanLogs(scanResultId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(scanLogs).where(eq(scanLogs.scanResultId, scanResultId)).orderBy(desc(scanLogs.timestamp)).limit(200);
}
function generateRandomCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return Array.from({ length: 12 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

// server/_core/cookies.ts
function isSecureRequest(req) {
  if (req.protocol === "https") return true;
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;
  const protoList = Array.isArray(forwardedProto) ? forwardedProto : forwardedProto.split(",");
  return protoList.some((proto) => proto.trim().toLowerCase() === "https");
}
function getSessionCookieOptions(req) {
  const secure = isSecureRequest(req);
  return {
    httpOnly: true,
    path: "/",
    sameSite: secure ? "none" : "lax",
    secure
  };
}

// server/_core/auth-simple.ts
console.log("\u{1F4DD} Loading auth-simple.ts...");
var ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@fivex.local";
var ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "@xtron123";
console.log(`\u2705 Admin credentials loaded - Email: ${ADMIN_EMAIL}`);
function registerSimpleAuthRoutes(app) {
  console.log("\u{1F680} Registering simple auth routes...");
  app.get("/login", (req, res) => {
    console.log("\u2705 /login route accessed");
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FiveX.check - Admin Login</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', sans-serif;
      background: #0a0f1e;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow: hidden;
    }
    .background {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 0;
    }
    .gradient {
      position: absolute;
      width: 100%;
      height: 100%;
      background: radial-gradient(circle at 50% 50%, rgba(139, 92, 246, 0.15) 0%, transparent 50%);
      animation: pulse 8s ease-in-out infinite;
    }
    .grid {
      position: absolute;
      width: 100%;
      height: 100%;
      background-image: 
        linear-gradient(rgba(139, 92, 246, 0.1) 1px, transparent 1px),
        linear-gradient(90deg, rgba(139, 92, 246, 0.1) 1px, transparent 1px);
      background-size: 50px 50px;
      animation: gridMove 20s linear infinite;
    }
    @keyframes pulse { 0%,100%{opacity:0.5;transform:scale(1);} 50%{opacity:0.8;transform:scale(1.2);} }
    @keyframes gridMove { 0%{transform:translateY(0);} 100%{transform:translateY(50px);} }
    .login-container {
      position: relative;
      z-index: 1;
      width: 100%;
      max-width: 420px;
      padding: 2rem;
    }
    .logo { text-align: center; margin-bottom: 2rem; }
    .logo h1 {
      font-size: 2.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }
    .logo p { color: #94a3b8; font-size: 0.875rem; font-weight: 500; }
    .login-card {
      background: rgba(15, 25, 50, 0.8);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(139, 92, 246, 0.2);
      border-radius: 24px;
      padding: 2rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }
    .login-header { text-align: center; margin-bottom: 2rem; }
    .login-header h2 { color: #f0faff; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; }
    .login-header p { color: #94a3b8; font-size: 0.875rem; }
    .form-group { margin-bottom: 1.5rem; }
    .form-group label {
      display: block;
      color: #f0faff;
      font-size: 0.875rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }
    .input-wrapper input {
      width: 100%;
      padding: 0.875rem 1rem;
      background: rgba(26, 37, 66, 0.8);
      border: 2px solid rgba(139, 92, 246, 0.2);
      border-radius: 12px;
      color: #f0faff;
      font-size: 1rem;
      transition: all 0.3s ease;
    }
    .input-wrapper input:focus {
      outline: none;
      border-color: #8b5cf6;
      background: rgba(26, 37, 66, 1);
      box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
    }
    .login-btn {
      width: 100%;
      padding: 0.875rem;
      background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);
      border: none;
      border-radius: 12px;
      color: white;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      margin-bottom: 1rem;
    }
    .login-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px -5px rgba(139, 92, 246, 0.5); }
    .discord-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      padding: 0.75rem 1rem;
      margin-top: 0.5rem;
      background: rgba(88, 101, 242, 0.15);
      border: 2px solid rgba(88, 101, 242, 0.8);
      border-radius: 12px;
      color: #a5b4fc;
      font-size: 0.95rem;
      font-weight: 600;
      text-align: center;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.3s ease;
      position: relative;
      animation: neonGlow 2s ease-in-out infinite;
    }
    .discord-btn:hover {
      background: rgba(88, 101, 242, 0.35);
      border-color: #7289da;
      color: #c7d2fe;
      transform: translateY(-2px);
      animation: none;
      box-shadow: 0 0 25px rgba(88, 101, 242, 0.7), inset 0 0 20px rgba(88, 101, 242, 0.1);
    }
    .discord-btn svg { flex-shrink: 0; }
    @keyframes neonGlow {
      0%, 100% { box-shadow: 0 0 8px rgba(88, 101, 242, 0.5), 0 0 20px rgba(88, 101, 242, 0.2); }
      50% { box-shadow: 0 0 20px rgba(88, 101, 242, 0.8), 0 0 40px rgba(88, 101, 242, 0.4); }
    }
    .back-home-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      margin-top: 1rem;
      padding: 0.6rem 1.25rem;
      background: transparent;
      border: 2px solid rgba(139, 92, 246, 0.4);
      border-radius: 12px;
      color: #a5b4fc;
      font-size: 0.9rem;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.3s ease;
    }
    .back-home-btn:hover {
      background: rgba(139, 92, 246, 0.2);
      border-color: #8b5cf6;
      color: #c7d2fe;
    }
    .login-footer {
      text-align: center;
      margin-top: 1.5rem;
      color: #64748b;
      font-size: 0.75rem;
    }
    .login-footer a { color: #8b5cf6; text-decoration: none; font-weight: 600; }
    .alert {
      position: fixed;
      top: 2rem;
      right: 2rem;
      padding: 1rem 1.5rem;
      background: linear-gradient(135deg, #ff4444 0%, #ff6b6b 100%);
      border-radius: 12px;
      color: white;
      font-weight: 600;
      z-index: 1000;
      animation: slideIn 0.3s ease;
    }
    @keyframes slideIn { from{transform:translateX(100%);opacity:0;} to{transform:translateX(0);opacity:1;} }
    .loading { position: relative; pointer-events: none; opacity: 0.7; }
    .loading::after {
      content: '';
      position: absolute;
      width: 20px;
      height: 20px;
      top: 50%;
      left: 50%;
      margin-left: -10px;
      margin-top: -10px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="background"><div class="gradient"></div><div class="grid"></div></div>
  <div class="login-container">
    <div class="logo"><h1>FiveX.check</h1><p>Professional FiveM & PC Security Scanner</p></div>
    <div class="login-card">
      <div class="login-header"><h2>Admin Login</h2><p>Enter your credentials</p></div>
      <form id="loginForm" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label>Email</label>
          <div class="input-wrapper"><input type="email" id="email" required placeholder="Enter your email" /></div>
        </div>
        <div class="form-group">
          <label>Password</label>
          <div class="input-wrapper"><input type="password" id="password" required placeholder="Enter your password" /></div>
        </div>
        <button type="submit" id="loginBtn" class="login-btn">Access Dashboard</button>
        <a href="https://discord.gg/sQQXgYk8" target="_blank" rel="noopener noreferrer" class="discord-btn">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
          <span>Join Discord</span>
        </a>
        <div style="text-align:center;">
          <a href="/" class="back-home-btn">\u2190 Back To Home</a>
        </div>
      </form>
    </div>
    <div class="login-footer">\xA9 2026 FiveX.check By XTRON</div>
  </div>
  <script>
    async function handleLogin(event) {
      event.preventDefault();
      const btn = document.getElementById('loginBtn');
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      btn.classList.add('loading'); btn.textContent = 'Authenticating...';
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ email, password })
        });
        if (response.ok) { window.location.href = '/'; } 
        else { 
          const errorMsg = await response.text();
          showAlert(errorMsg || 'Invalid credentials');
          btn.classList.remove('loading'); btn.textContent = 'Access Dashboard';
        }
      } catch (error) {
        showAlert('Connection error');
        btn.classList.remove('loading'); btn.textContent = 'Access Dashboard';
      }
    }
    function showAlert(message) {
      const alertDiv = document.createElement('div');
      alertDiv.className = 'alert';
      alertDiv.textContent = message;
      document.body.appendChild(alertDiv);
      setTimeout(() => alertDiv.remove(), 3000);
    }
  </script>
</body>
</html>`);
  });
  app.post("/api/auth/login", async (req, res) => {
    console.log("\u2705 /api/auth/login accessed");
    const { email, password } = req.body;
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      console.log("\u2705 Login successful, creating admin user...");
      try {
        await upsertUser({
          openId: "admin-user",
          name: "Administrator",
          email,
          loginMethod: "simple",
          lastSignedIn: /* @__PURE__ */ new Date(),
          role: "admin"
          // ← এই লাইনটা যোগ করো
        });
        console.log("\u2705 Admin user created/updated in database");
        const sessionToken = Math.random().toString(36).substring(2);
        const cookieOptions = getSessionCookieOptions(req);
        res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
        console.log("\u2705 Session created, redirecting to dashboard");
        res.redirect(302, "/");
      } catch (error) {
        console.error("\u274C Database error:", error);
        res.status(500).send("Database error");
      }
    } else {
      res.status(401).send("Invalid credentials");
    }
  });
  app.post("/api/auth/logout", (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: "/" });
    res.json({ success: true });
  });
  app.get("/api/auth/me", async (req, res) => {
    const token = req.cookies?.[COOKIE_NAME];
    if (token) {
      const user = await getUserByOpenId("admin-user");
      if (user) {
        res.json({ user: {
          id: user.id,
          name: user.name || "Admin",
          email: user.email || ADMIN_EMAIL,
          role: user.role || "admin"
        } });
      } else {
        res.json({ user: {
          id: 1,
          name: "Admin",
          email: ADMIN_EMAIL,
          role: "admin"
        } });
      }
    } else {
      res.status(401).json({ error: "Not authenticated" });
    }
  });
  console.log("\u2705 Simple auth routes registered!");
  console.log("   - GET /login");
  console.log("   - POST /api/auth/login");
  console.log("   - POST /api/auth/logout");
  console.log("   - GET /api/auth/me");
}

// server/_core/systemRouter.ts
import { z } from "zod";

// server/_core/notification.ts
import { TRPCError } from "@trpc/server";
var TITLE_MAX_LENGTH = 1200;
var CONTENT_MAX_LENGTH = 2e4;
var trimValue = (value) => value.trim();
var isNonEmptyString = (value) => typeof value === "string" && value.trim().length > 0;
var buildEndpointUrl = (baseUrl) => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(
    "webdevtoken.v1.WebDevService/SendNotification",
    normalizedBase
  ).toString();
};
var validatePayload = (input) => {
  if (!isNonEmptyString(input.title)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification title is required."
    });
  }
  if (!isNonEmptyString(input.content)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification content is required."
    });
  }
  const title = trimValue(input.title);
  const content = trimValue(input.content);
  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`
    });
  }
  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`
    });
  }
  return { title, content };
};
async function notifyOwner(payload) {
  const { title, content } = validatePayload(payload);
  if (!ENV.forgeApiUrl) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service URL is not configured."
    });
  }
  if (!ENV.forgeApiKey) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service API key is not configured."
    });
  }
  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1"
      },
      body: JSON.stringify({ title, content })
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      console.warn(
        `[Notification] Failed to notify owner (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`
      );
      return false;
    }
    return true;
  } catch (error) {
    console.warn("[Notification] Error calling notification service:", error);
    return false;
  }
}

// server/_core/trpc.ts
import { initTRPC, TRPCError as TRPCError2 } from "@trpc/server";
import superjson from "superjson";
var t = initTRPC.context().create({
  transformer: superjson
});
var router = t.router;
var publicProcedure = t.procedure;
var requireUser = t.middleware(async (opts) => {
  const { ctx, next } = opts;
  if (!ctx.user) {
    throw new TRPCError2({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return next({
    ctx: {
      ...ctx,
      user: ctx.user
    }
  });
});
var protectedProcedure = t.procedure.use(requireUser);
var adminProcedure = t.procedure.use(
  t.middleware(async (opts) => {
    const { ctx, next } = opts;
    if (!ctx.user || ctx.user.role !== "admin") {
      throw new TRPCError2({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }
    return next({
      ctx: {
        ...ctx,
        user: ctx.user
      }
    });
  })
);

// server/_core/systemRouter.ts
var systemRouter = router({
  // Health check endpoint - public
  health: publicProcedure.input(
    z.object({
      timestamp: z.number().min(0, "timestamp cannot be negative")
    })
  ).query(() => ({
    ok: true
  })),
  // Notify owner endpoint - admin only
  notifyOwner: adminProcedure.input(
    z.object({
      title: z.string().min(1, "title is required"),
      content: z.string().min(1, "content is required")
    })
  ).mutation(async ({ input }) => {
    const delivered = await notifyOwner(input);
    return {
      success: delivered
    };
  })
});

// server/routers.ts
import { TRPCError as TRPCError3 } from "@trpc/server";
import { z as z2 } from "zod";
function dateForBD(d) {
  if (d == null) return d;
  const t2 = typeof d === "string" ? new Date(d).getTime() : d.getTime();
  return new Date(t2 - 6 * 60 * 60 * 1e3);
}
var appRouter = router({
  system: systemRouter,
  // Scan Code Management
  scanCode: router({
    generate: publicProcedure.input(z2.object({ expirationHours: z2.number().int().min(1).max(720).default(24) })).mutation(async ({ input }) => {
      try {
        const code = await generateScanCode(1, input.expirationHours);
        return { code, success: true };
      } catch (error) {
        console.error("\u274C Error generating scan code:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to generate scan code"
        });
      }
    }),
    list: publicProcedure.query(async () => {
      try {
        const codes = await getAllScanCodes();
        return codes.map((c) => ({
          ...c,
          createdAt: dateForBD(c.createdAt),
          expiresAt: dateForBD(c.expiresAt),
          usedAt: dateForBD(c.usedAt)
        }));
      } catch (error) {
        console.error("\u274C Error listing scan codes:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to fetch scan codes"
        });
      }
    }),
    validate: publicProcedure.input(z2.object({ code: z2.string(), deviceName: z2.string() })).mutation(async ({ input }) => {
      try {
        return await validateAndUseScanCode(input.code, input.deviceName);
      } catch (error) {
        console.error("\u274C Error validating scan code:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to validate scan code"
        });
      }
    }),
    // ✅ Now public – no login required
    delete: publicProcedure.input(z2.object({ codeId: z2.number() })).mutation(async ({ input }) => {
      try {
        await deleteScanCode(input.codeId);
        return { success: true };
      } catch (error) {
        console.error("\u274C Error deleting scan code:", error);
        if (error instanceof TRPCError3) throw error;
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to delete scan code"
        });
      }
    })
  }),
  // Scan Results Management
  scanResult: router({
    create: publicProcedure.input(z2.object({
      scanCodeId: z2.number(),
      deviceName: z2.string(),
      osVersion: z2.string().optional(),
      systemInfo: z2.any().optional()
    })).mutation(async ({ input }) => {
      try {
        console.log("\u{1F4DD} Creating scan result with input:", input);
        const result = await createScanResult({
          scanCodeId: input.scanCodeId,
          deviceName: input.deviceName,
          osVersion: input.osVersion,
          systemInfo: input.systemInfo || null,
          scanStartTime: /* @__PURE__ */ new Date(),
          scanStatus: "in_progress"
        });
        console.log("\u2705 Scan result created:", result);
        return result;
      } catch (error) {
        console.error("\u274C Error in scanResult.create:", error);
        let errorMessage = "Unknown error creating scan result";
        if (error instanceof Error) {
          errorMessage = error.message;
        }
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: errorMessage
        });
      }
    }),
    list: publicProcedure.query(async () => {
      try {
        const results = await getAllScanResults();
        return results.map((r) => ({
          ...r,
          scanStartTime: dateForBD(r.scanStartTime),
          scanEndTime: dateForBD(r.scanEndTime),
          createdAt: dateForBD(r.createdAt)
        }));
      } catch (error) {
        console.error("\u274C Error listing scan results:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to fetch scan results"
        });
      }
    }),
    getWithFiles: publicProcedure.input(z2.object({ scanResultId: z2.number() })).query(async ({ input }) => {
      try {
        const data = await getScanResultWithFiles(input.scanResultId);
        if (!data) return null;
        return {
          ...data,
          scanStartTime: dateForBD(data.scanStartTime),
          scanEndTime: dateForBD(data.scanEndTime),
          createdAt: dateForBD(data.createdAt),
          files: (data.files || []).map((f) => ({
            ...f,
            createdDate: dateForBD(f.createdDate),
            modifiedDate: dateForBD(f.modifiedDate)
          }))
        };
      } catch (error) {
        console.error("\u274C Error getting scan result with files:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to fetch scan result"
        });
      }
    }),
    updateStatus: publicProcedure.input(z2.object({
      scanResultId: z2.number(),
      status: z2.enum(["in_progress", "completed", "failed"]),
      overallRiskLevel: z2.enum(["suspicious", "warning", "moderate", "safe"]).optional()
    })).mutation(async ({ input }) => {
      try {
        await updateScanResultStatus(
          input.scanResultId,
          input.status,
          input.status === "completed" ? /* @__PURE__ */ new Date() : void 0,
          input.overallRiskLevel
        );
        return { success: true };
      } catch (error) {
        console.error("\u274C Error updating scan result status:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to update scan status"
        });
      }
    }),
    addFiles: publicProcedure.input(z2.object({
      scanResultId: z2.number(),
      files: z2.array(z2.object({
        filePath: z2.string(),
        fileName: z2.string(),
        fileType: z2.string().optional(),
        fileSize: z2.number().optional(),
        riskLevel: z2.enum(["suspicious", "warning", "moderate", "safe"]),
        detectionReason: z2.string().optional(),
        fileHash: z2.string().optional(),
        isFiveMMod: z2.boolean().optional(),
        isSystemFile: z2.boolean().optional(),
        windowsDetails: z2.string().optional()
      }))
    })).mutation(async ({ input }) => {
      try {
        await addScanFiles(input.scanResultId, input.files);
        return { success: true };
      } catch (error) {
        console.error("\u274C Error adding scan files:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to add files"
        });
      }
    }),
    setCounts: publicProcedure.input(z2.object({
      scanResultId: z2.number(),
      totalFilesScanned: z2.number(),
      suspiciousCount: z2.number(),
      warningCount: z2.number(),
      moderateCount: z2.number(),
      safeCount: z2.number()
    })).mutation(async ({ input }) => {
      try {
        await setScanResultCounts(input.scanResultId, {
          totalFilesScanned: input.totalFilesScanned,
          suspiciousCount: input.suspiciousCount,
          warningCount: input.warningCount,
          moderateCount: input.moderateCount,
          safeCount: input.safeCount
        });
        return { success: true };
      } catch (error) {
        console.error("\u274C Error setting scan counts:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to set scan counts"
        });
      }
    })
  }),
  // Scan Logs Management
  scanLog: router({
    add: publicProcedure.input(z2.object({
      scanResultId: z2.number(),
      logLevel: z2.enum(["INFO", "SUCCESS", "WARN", "ERROR", "DEBUG"]).default("INFO"),
      message: z2.string(),
      filePath: z2.string().optional().default(""),
      progress: z2.number().min(0).max(100).optional()
    })).mutation(async ({ input }) => {
      try {
        await addScanLog({
          scanResultId: input.scanResultId,
          logLevel: input.logLevel,
          message: input.message,
          filePath: input.filePath,
          progress: input.progress,
          timestamp: /* @__PURE__ */ new Date()
        });
        return { success: true };
      } catch (error) {
        console.error("\u274C Error adding scan log:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to add log"
        });
      }
    }),
    getRecent: publicProcedure.input(z2.object({ scanResultId: z2.number() })).query(async ({ input }) => {
      try {
        const logs = await getRecentScanLogs(input.scanResultId);
        return (logs || []).map((log) => ({ ...log, timestamp: dateForBD(log.timestamp) }));
      } catch (error) {
        console.error("\u274C Error getting recent logs:", error);
        throw new TRPCError3({
          code: "INTERNAL_SERVER_ERROR",
          message: error instanceof Error ? error.message : "Failed to fetch logs"
        });
      }
    })
  })
});

// shared/_core/errors.ts
var HttpError = class extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "HttpError";
  }
};
var ForbiddenError = (msg) => new HttpError(403, msg);

// server/_core/sdk.ts
import { SignJWT, jwtVerify } from "jose";
var isNonEmptyString2 = (value) => typeof value === "string" && value.length > 0;
var SimpleSDKServer = class {
  constructor() {
    console.log("\u2705 Simple SDK initialized (OAuth removed)");
  }
  getSessionSecret() {
    const secret = ENV.cookieSecret;
    return new TextEncoder().encode(secret);
  }
  /**
   * Create a session token for admin user
   */
  async createSessionToken(openId, options = {}) {
    return this.signSession(
      {
        openId,
        appId: ENV.appId || "fivex-check",
        name: options.name || "Admin"
      },
      options
    );
  }
  async signSession(payload, options = {}) {
    const issuedAt = Date.now();
    const expiresInMs = options.expiresInMs ?? ONE_YEAR_MS;
    const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1e3);
    const secretKey = this.getSessionSecret();
    return new SignJWT({
      openId: payload.openId,
      appId: payload.appId,
      name: payload.name
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setExpirationTime(expirationSeconds).sign(secretKey);
  }
  async verifySession(cookieValue) {
    if (!cookieValue) {
      return null;
    }
    try {
      const secretKey = this.getSessionSecret();
      const { payload } = await jwtVerify(cookieValue, secretKey, {
        algorithms: ["HS256"]
      });
      const { openId, appId, name } = payload;
      if (!isNonEmptyString2(openId) || !isNonEmptyString2(appId) || !isNonEmptyString2(name)) {
        return null;
      }
      return { openId, appId, name };
    } catch (error) {
      return null;
    }
  }
  async authenticateRequest(req) {
    const cookies = this.parseCookies(req.headers.cookie);
    const sessionCookie = cookies.get(COOKIE_NAME);
    const session = await this.verifySession(sessionCookie);
    if (!session) {
      throw ForbiddenError("Invalid session cookie");
    }
    const sessionUserId = session.openId;
    const signedInAt = /* @__PURE__ */ new Date();
    let user = await getUserByOpenId(sessionUserId);
    if (!user) {
      await upsertUser({
        openId: sessionUserId,
        name: "Admin",
        email: process.env.ADMIN_EMAIL || "admin@fivex.local",
        loginMethod: "simple",
        lastSignedIn: signedInAt
      });
      user = await getUserByOpenId(sessionUserId);
    }
    if (!user) {
      throw ForbiddenError("User not found");
    }
    await upsertUser({
      openId: user.openId,
      lastSignedIn: signedInAt
    });
    return user;
  }
  parseCookies(cookieHeader) {
    if (!cookieHeader) {
      return /* @__PURE__ */ new Map();
    }
    const cookies = /* @__PURE__ */ new Map();
    cookieHeader.split(";").forEach((cookie) => {
      const parts = cookie.split("=");
      if (parts.length >= 2) {
        cookies.set(parts[0].trim(), parts[1].trim());
      }
    });
    return cookies;
  }
  // Dummy methods for compatibility
  async exchangeCodeForToken() {
    throw new Error("OAuth not supported - use simple auth");
  }
  async getUserInfo() {
    throw new Error("OAuth not supported - use simple auth");
  }
};
var sdk = new SimpleSDKServer();

// server/_core/context.ts
async function createContext(opts) {
  let user = null;
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    user = null;
  }
  return {
    req: opts.req,
    res: opts.res,
    user
  };
}

// server/_core/vite.ts
import express from "express";
import fs2 from "fs";
import { nanoid } from "nanoid";
import path2 from "path";
import { createServer as createViteServer } from "vite";

// vite.config.ts
import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";
var PROJECT_ROOT = import.meta.dirname;
var LOG_DIR = path.join(PROJECT_ROOT, ".manus-logs");
var MAX_LOG_SIZE_BYTES = 1 * 1024 * 1024;
var TRIM_TARGET_BYTES = Math.floor(MAX_LOG_SIZE_BYTES * 0.6);
function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}
function trimLogFile(logPath, maxSize) {
  try {
    if (!fs.existsSync(logPath) || fs.statSync(logPath).size <= maxSize) {
      return;
    }
    const lines = fs.readFileSync(logPath, "utf-8").split("\n");
    const keptLines = [];
    let keptBytes = 0;
    const targetSize = TRIM_TARGET_BYTES;
    for (let i = lines.length - 1; i >= 0; i--) {
      const lineBytes = Buffer.byteLength(`${lines[i]}
`, "utf-8");
      if (keptBytes + lineBytes > targetSize) break;
      keptLines.unshift(lines[i]);
      keptBytes += lineBytes;
    }
    fs.writeFileSync(logPath, keptLines.join("\n"), "utf-8");
  } catch {
  }
}
function writeToLogFile(source, entries) {
  if (entries.length === 0) return;
  ensureLogDir();
  const logPath = path.join(LOG_DIR, `${source}.log`);
  const lines = entries.map((entry) => {
    const ts = (/* @__PURE__ */ new Date()).toISOString();
    return `[${ts}] ${JSON.stringify(entry)}`;
  });
  fs.appendFileSync(logPath, `${lines.join("\n")}
`, "utf-8");
  trimLogFile(logPath, MAX_LOG_SIZE_BYTES);
}
function vitePluginManusDebugCollector() {
  return {
    name: "manus-debug-collector",
    transformIndexHtml(html) {
      if (process.env.NODE_ENV === "production") {
        return html;
      }
      return {
        html,
        tags: [
          {
            tag: "script",
            attrs: {
              src: "/__manus__/debug-collector.js",
              defer: true
            },
            injectTo: "head"
          }
        ]
      };
    },
    configureServer(server) {
      server.middlewares.use("/__manus__/logs", (req, res, next) => {
        if (req.method !== "POST") {
          return next();
        }
        const handlePayload = (payload) => {
          if (payload.consoleLogs?.length > 0) {
            writeToLogFile("browserConsole", payload.consoleLogs);
          }
          if (payload.networkRequests?.length > 0) {
            writeToLogFile("networkRequests", payload.networkRequests);
          }
          if (payload.sessionEvents?.length > 0) {
            writeToLogFile("sessionReplay", payload.sessionEvents);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true }));
        };
        const reqBody = req.body;
        if (reqBody && typeof reqBody === "object") {
          try {
            handlePayload(reqBody);
          } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: String(e) }));
          }
          return;
        }
        let body = "";
        req.on("data", (chunk) => {
          body += chunk.toString();
        });
        req.on("end", () => {
          try {
            const payload = JSON.parse(body);
            handlePayload(payload);
          } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: String(e) }));
          }
        });
      });
    }
  };
}
var plugins = [react(), tailwindcss(), jsxLocPlugin(), vitePluginManusRuntime(), vitePluginManusDebugCollector()];
var vite_config_default = defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  envDir: path.resolve(import.meta.dirname),
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    host: true,
    allowedHosts: [
      ".manuspre.computer",
      ".manus.computer",
      ".manus-asia.computer",
      ".manuscomputer.ai",
      ".manusvm.computer",
      "localhost",
      "127.0.0.1"
    ],
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/_core/vite.ts
async function setupVite(app, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    server: serverOptions,
    appType: "custom"
  });
  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app) {
  const distPath = process.env.NODE_ENV === "development" ? path2.resolve(import.meta.dirname, "../..", "dist", "public") : path2.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(express.static(distPath));
  app.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/_core/index.ts
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}
async function findAvailablePort(startPort = 3e3) {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}
async function startServer() {
  const app = express2();
  const server = createServer(app);
  app.use(express2.json({ limit: "50mb" }));
  app.use(express2.urlencoded({ limit: "50mb", extended: true }));
  app.use(cookieParser());
  registerSimpleAuthRoutes(app);
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext
    })
  );
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);
  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}
startServer().catch(console.error);
