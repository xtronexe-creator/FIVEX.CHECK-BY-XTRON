CREATE TABLE `scan_codes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`code` varchar(32) NOT NULL,
	`status` enum('active','used','expired') NOT NULL DEFAULT 'active',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp NOT NULL,
	`usedAt` timestamp,
	`usedByDevice` varchar(255),
	`createdByUserId` int NOT NULL,
	CONSTRAINT `scan_codes_id` PRIMARY KEY(`id`),
	CONSTRAINT `scan_codes_code_unique` UNIQUE(`code`)
);
--> statement-breakpoint
CREATE TABLE `scan_files` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanResultId` int NOT NULL,
	`filePath` text NOT NULL,
	`fileName` varchar(255) NOT NULL,
	`fileType` varchar(50),
	`fileSize` int,
	`riskLevel` enum('suspicious','warning','moderate','safe') NOT NULL,
	`detectionReason` text,
	`fileHash` varchar(128),
	`createdDate` timestamp,
	`modifiedDate` timestamp,
	`isFiveMMod` int DEFAULT 0,
	`isSystemFile` int DEFAULT 0,
	`windowsDetails` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_files_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanCodeId` int NOT NULL,
	`deviceName` varchar(255) NOT NULL,
	`osVersion` varchar(255),
	`scanStartTime` timestamp NOT NULL,
	`scanEndTime` timestamp,
	`totalFilesScanned` int DEFAULT 0,
	`suspiciousCount` int DEFAULT 0,
	`warningCount` int DEFAULT 0,
	`moderateCount` int DEFAULT 0,
	`safeCount` int DEFAULT 0,
	`overallRiskLevel` enum('critical','high','medium','low','safe') DEFAULT 'safe',
	`scanStatus` enum('in_progress','completed','failed') DEFAULT 'in_progress',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_results_id` PRIMARY KEY(`id`)
);
