CREATE TYPE "public"."log_level" AS ENUM('INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG');--> statement-breakpoint
CREATE TYPE "public"."risk_level" AS ENUM('suspicious', 'warning', 'moderate', 'safe');--> statement-breakpoint
CREATE TYPE "public"."role" AS ENUM('user', 'admin');--> statement-breakpoint
CREATE TYPE "public"."scan_status" AS ENUM('in_progress', 'completed', 'failed');--> statement-breakpoint
CREATE TYPE "public"."status" AS ENUM('active', 'used', 'expired');--> statement-breakpoint
CREATE TABLE "scan_codes" (
	"id" serial PRIMARY KEY NOT NULL,
	"code" varchar(12) NOT NULL,
	"status" "status" DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"used_by_device" varchar(255),
	"created_by_user_id" integer,
	CONSTRAINT "scan_codes_code_unique" UNIQUE("code")
);
--> statement-breakpoint
CREATE TABLE "scan_files" (
	"id" serial PRIMARY KEY NOT NULL,
	"scan_result_id" integer,
	"file_path" text NOT NULL,
	"file_name" varchar(255) NOT NULL,
	"file_type" varchar(50),
	"file_size" integer,
	"risk_level" "risk_level" NOT NULL,
	"detection_reason" text,
	"file_hash" varchar(64),
	"created_date" timestamp,
	"modified_date" timestamp,
	"is_fivem_mod" boolean DEFAULT false,
	"is_system_file" boolean DEFAULT false,
	"windows_details" text
);
--> statement-breakpoint
CREATE TABLE "scan_logs" (
	"id" serial PRIMARY KEY NOT NULL,
	"scan_result_id" integer,
	"log_level" "log_level" NOT NULL,
	"message" text NOT NULL,
	"file_path" text,
	"progress" integer,
	"metadata" text,
	"timestamp" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_results" (
	"id" serial PRIMARY KEY NOT NULL,
	"scan_code_id" integer,
	"device_name" varchar(255) NOT NULL,
	"os_version" varchar(255),
	"scan_start_time" timestamp DEFAULT now() NOT NULL,
	"scan_end_time" timestamp,
	"total_files_scanned" integer DEFAULT 0,
	"suspicious_count" integer DEFAULT 0,
	"warning_count" integer DEFAULT 0,
	"moderate_count" integer DEFAULT 0,
	"safe_count" integer DEFAULT 0,
	"overall_risk_level" "risk_level",
	"scan_status" "scan_status" DEFAULT 'in_progress' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"open_id" varchar(64) NOT NULL,
	"name" text,
	"email" varchar(320),
	"login_method" varchar(64),
	"role" "role" DEFAULT 'user' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"last_signed_in" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "users_open_id_unique" UNIQUE("open_id")
);
--> statement-breakpoint
ALTER TABLE "scan_codes" ADD CONSTRAINT "scan_codes_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_files" ADD CONSTRAINT "scan_files_scan_result_id_scan_results_id_fk" FOREIGN KEY ("scan_result_id") REFERENCES "public"."scan_results"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_logs" ADD CONSTRAINT "scan_logs_scan_result_id_scan_results_id_fk" FOREIGN KEY ("scan_result_id") REFERENCES "public"."scan_results"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_scan_code_id_scan_codes_id_fk" FOREIGN KEY ("scan_code_id") REFERENCES "public"."scan_codes"("id") ON DELETE no action ON UPDATE no action;