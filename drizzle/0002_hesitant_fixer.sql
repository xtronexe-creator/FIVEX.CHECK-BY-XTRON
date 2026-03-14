CREATE TABLE `scan_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanResultId` int NOT NULL,
	`logLevel` enum('INFO','SUCCESS','WARN','ERROR','DEBUG') DEFAULT 'INFO',
	`message` text NOT NULL,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	`filePath` varchar(500),
	`progress` int,
	`metadata` text,
	CONSTRAINT `scan_logs_id` PRIMARY KEY(`id`)
);
