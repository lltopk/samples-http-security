CREATE TABLE http_security_mac_open_app (
                                            id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                            app_key VARCHAR(64) NOT NULL,
                                            app_secret VARCHAR(128) NOT NULL,
                                            app_name VARCHAR(100) NOT NULL,
                                            status TINYINT NOT NULL DEFAULT 1 COMMENT '1启用 0禁用',
                                            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                                            UNIQUE KEY uk_app_key (app_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;