-- MySQL 8 schema. Configure DATABASE_URL=mysql+pymysql://user:password@host/database.
-- Store no source document, raw OCR text, or unmasked government identifier here.
CREATE TABLE IF NOT EXISTS compliance_rules (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    rule_id VARCHAR(80) NOT NULL UNIQUE,
    name VARCHAR(180) NOT NULL,
    description TEXT NOT NULL,
    rule_type VARCHAR(50) NOT NULL,
    config_json JSON NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    version VARCHAR(40) NOT NULL,
    effective_from DATE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_compliance_rules_enabled (enabled, effective_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS application_records (
    id CHAR(36) NOT NULL PRIMARY KEY,
    document_name VARCHAR(180) NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    risk_level VARCHAR(30) NOT NULL,
    review_status VARCHAR(30) NOT NULL DEFAULT 'pending_review',
    reviewer_note TEXT NOT NULL,
    report_json JSON NOT NULL,
    created_at TIMESTAMP NOT NULL,
    reviewed_at TIMESTAMP NULL,
    INDEX idx_records_review_created (review_status, created_at),
    INDEX idx_records_risk_created (risk_level, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Demo-only examples. Confirm jurisdiction, scope, effective dates, and official
-- sources before enabling rules in a production workflow.
INSERT IGNORE INTO compliance_rules
    (rule_id, name, description, rule_type, config_json, enabled, version, effective_from)
VALUES
    ('pan_required_for_tax_application', 'PAN required for tax application',
     'Checks that a PAN format was detected.', 'field_presence', JSON_OBJECT('field', 'PAN', 'document_types', JSON_ARRAY('pan', 'pan_card', 'tax_application')), TRUE, 'demo-1', '2026-01-01'),
    ('aadhaar_checksum', 'Aadhaar checksum',
     'Screens format and Verhoeff checksum; does not verify issuance or identity.', 'field_presence', JSON_OBJECT('field', 'Aadhaar', 'document_types', JSON_ARRAY('aadhaar', 'identity')), TRUE, 'demo-1', '2026-01-01'),
    ('gstin_pan_consistency', 'GSTIN and PAN consistency',
     'Checks detected GSTIN and PAN embedded identifier consistency.', 'gstin_pan_match', JSON_OBJECT(), TRUE, 'demo-1', '2026-01-01');
