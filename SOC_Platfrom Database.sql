-- ═══════════════════════════════════════════════════════════════════
--  SOC Platform — Full Schema  (SQL Server / T-SQL)
--  Run in SSMS against your SOC_Platform database
-- ═══════════════════════════════════════════════════════════════════
Create DATABASE SOC_Platform;
USE SOC_Platform;
GO

-- ─────────────────────────────────────────────────────────────────
-- 1. USERS  (core auth table)
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.users (
    id                    INT           IDENTITY(1,1) PRIMARY KEY,
    username              NVARCHAR(80)  NOT NULL UNIQUE,
    email                 NVARCHAR(120) NOT NULL UNIQUE,
    password_hash         NVARCHAR(255) NOT NULL,
    role                  NVARCHAR(20)  NOT NULL DEFAULT 'analyst',
    failed_login_attempts INT           NOT NULL DEFAULT 0,
    locked_until          DATETIME2     NULL,
    reset_token           NVARCHAR(100) NULL,
    reset_token_expiry    DATETIME2     NULL,
    totp_secret           NVARCHAR(64)  NULL,
    totp_enabled          BIT           NOT NULL DEFAULT 0,
    created_at            DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 2. ROLES
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.roles (
    id          INT           IDENTITY(1,1) PRIMARY KEY,
    name        NVARCHAR(50)  NOT NULL UNIQUE,       -- viewer | analyst | admin
    description NVARCHAR(200) NULL,
    level       INT           NOT NULL DEFAULT 0,    -- 0=viewer 1=analyst 2=admin
    is_system   BIT           NOT NULL DEFAULT 0,    -- 1 = cannot be deleted
    created_at  DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 3. PERMISSIONS
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.permissions (
    id          INT           IDENTITY(1,1) PRIMARY KEY,
    name        NVARCHAR(100) NOT NULL UNIQUE,       -- 'firewall:write'
    resource    NVARCHAR(50)  NOT NULL,              -- 'firewall'
    action      NVARCHAR(50)  NOT NULL,              -- 'write'
    description NVARCHAR(200) NULL,
    CONSTRAINT uq_perm_resource_action UNIQUE (resource, action)
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 4. ROLE_PERMISSIONS  (many-to-many join)
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.role_permissions (
    role_id       INT NOT NULL
        CONSTRAINT fk_rp_role REFERENCES dbo.roles(id)       ON DELETE CASCADE,
    permission_id INT NOT NULL
        CONSTRAINT fk_rp_perm REFERENCES dbo.permissions(id) ON DELETE CASCADE,
    CONSTRAINT pk_role_permissions PRIMARY KEY (role_id, permission_id)
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 5. USER_ROLES  (assignment: who holds which role)
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.user_roles (
    id             INT      IDENTITY(1,1) PRIMARY KEY,
    user_id        INT      NOT NULL
        CONSTRAINT fk_ur_user     REFERENCES dbo.users(id) ON DELETE CASCADE,
    role_id        INT      NOT NULL
        CONSTRAINT fk_ur_role     REFERENCES dbo.roles(id) ON DELETE CASCADE,
    assigned_by_id INT      NULL
        CONSTRAINT fk_ur_assigner REFERENCES dbo.users(id) ON DELETE NO ACTION,
    assigned_at    DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    expires_at     DATETIME2 NULL,          -- NULL = permanent
    is_active      BIT       NOT NULL DEFAULT 1,
    CONSTRAINT uq_user_role UNIQUE (user_id, role_id)
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 6. LOGIN_HISTORY  (every login attempt, success + failure)
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.login_history (
    id             INT           IDENTITY(1,1) PRIMARY KEY,
    user_id        INT           NULL
        CONSTRAINT fk_lh_user REFERENCES dbo.users(id) ON DELETE SET NULL,
    username       NVARCHAR(80)  NOT NULL,
    ip_address     NVARCHAR(45)  NOT NULL,
    user_agent     NVARCHAR(500) NULL,
    success        BIT           NOT NULL,
    failure_reason NVARCHAR(100) NULL,   -- wrong_password|not_found|account_locked|rate_limited
    role_snapshot  NVARCHAR(50)  NULL,   -- role at login time
    login_at       DATETIME2     NOT NULL DEFAULT GETUTCDATE(),
    logout_at      DATETIME2     NULL    -- stamped on logout
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 7. CASES
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.cases (
    id              INT           IDENTITY(1,1) PRIMARY KEY,
    case_id         NVARCHAR(20)  NOT NULL UNIQUE,
    title           NVARCHAR(200) NOT NULL,
    description     NVARCHAR(MAX) NULL,
    severity        NVARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    status          NVARCHAR(20)  NOT NULL DEFAULT 'OPEN',
    source          NVARCHAR(50)  NOT NULL DEFAULT 'manual',
    incident_ref    NVARCHAR(30)  NULL,
    src_ip          NVARCHAR(45)  NULL,
    attack_type     NVARCHAR(80)  NULL,
    mitre_tactic    NVARCHAR(100) NULL,
    mitre_technique NVARCHAR(100) NULL,
    created_by_id   INT           NULL REFERENCES dbo.users(id),
    assigned_to_id  INT           NULL REFERENCES dbo.users(id),
    created_at      DATETIME2     NOT NULL DEFAULT GETUTCDATE(),
    updated_at      DATETIME2     NOT NULL DEFAULT GETUTCDATE(),
    resolved_at     DATETIME2     NULL,
    sla_deadline    DATETIME2     NULL,
    deleted         BIT           NOT NULL DEFAULT 0,
    deleted_at      DATETIME2     NULL,
    deleted_by      NVARCHAR(80)  NULL
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 8. CASE_NOTES
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.case_notes (
    id         INT           IDENTITY(1,1) PRIMARY KEY,
    case_id    INT           NOT NULL REFERENCES dbo.cases(id) ON DELETE CASCADE,
    author_id  INT           NULL     REFERENCES dbo.users(id),
    body       NVARCHAR(MAX) NOT NULL,
    note_type  NVARCHAR(20)  NOT NULL DEFAULT 'comment',
    created_at DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 9. API_KEYS
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.api_keys (
    id         INT           IDENTITY(1,1) PRIMARY KEY,
    name       NVARCHAR(80)  NOT NULL,
    key_hash   NVARCHAR(128) NOT NULL UNIQUE,
    prefix     NVARCHAR(12)  NOT NULL,
    owner_id   INT           NULL REFERENCES dbo.users(id),
    scopes     NVARCHAR(200) NOT NULL DEFAULT 'read',
    created_at DATETIME2     NOT NULL DEFAULT GETUTCDATE(),
    last_used  DATETIME2     NULL,
    expires_at DATETIME2     NULL,
    active     BIT           NOT NULL DEFAULT 1
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 10. CORRELATION_RULES
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.correlation_rules (
    id            INT           IDENTITY(1,1) PRIMARY KEY,
    name          NVARCHAR(120) NOT NULL,
    description   NVARCHAR(MAX) NULL,
    rule_type     NVARCHAR(30)  NOT NULL DEFAULT 'threshold',
    conditions    NVARCHAR(MAX) NOT NULL,
    severity      NVARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    mitre_tactic  NVARCHAR(100) NULL,
    mitre_tech    NVARCHAR(100) NULL,
    enabled       BIT           NOT NULL DEFAULT 1,
    fire_count    INT           NOT NULL DEFAULT 0,
    last_fired    DATETIME2     NULL,
    created_at    DATETIME2     NOT NULL DEFAULT GETUTCDATE(),
    created_by_id INT           NULL REFERENCES dbo.users(id)
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 11. AUDIT_LOGS
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.audit_logs (
    id         INT           IDENTITY(1,1) PRIMARY KEY,
    user_id    INT           NULL REFERENCES dbo.users(id),
    action     NVARCHAR(80)  NOT NULL,
    target     NVARCHAR(200) NULL,
    detail     NVARCHAR(MAX) NULL,
    ip_address NVARCHAR(45)  NULL,
    timestamp  DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 12. IOC_ENTRIES
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.ioc_entries (
    id          INT           IDENTITY(1,1) PRIMARY KEY,
    ioc_type    NVARCHAR(20)  NOT NULL,
    value       NVARCHAR(512) NOT NULL,
    source      NVARCHAR(80)  NOT NULL DEFAULT 'manual',
    confidence  INT           NOT NULL DEFAULT 50,
    threat_type NVARCHAR(80)  NULL,
    description NVARCHAR(MAX) NULL,
    last_seen   DATETIME2     NOT NULL DEFAULT GETUTCDATE(),
    expires_at  DATETIME2     NULL,
    active      BIT           NOT NULL DEFAULT 1,
    CONSTRAINT uq_ioc_type_value UNIQUE (ioc_type, value)
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 13. NOTIFICATION_CONFIGS
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.notification_configs (
    id           INT           IDENTITY(1,1) PRIMARY KEY,
    name         NVARCHAR(80)  NOT NULL,
    channel      NVARCHAR(20)  NOT NULL,
    destination  NVARCHAR(512) NOT NULL,
    min_severity NVARCHAR(20)  NOT NULL DEFAULT 'HIGH',
    enabled      BIT           NOT NULL DEFAULT 1,
    created_at   DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 14. SECURITY_EVENTS
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.security_events (
    id          INT           IDENTITY(1,1) PRIMARY KEY,
    ip_address  NVARCHAR(45)  NOT NULL,
    attack_type NVARCHAR(50)  NOT NULL,
    severity    NVARCHAR(20)  NOT NULL DEFAULT 'HIGH',
    path        NVARCHAR(500) NULL,
    user_agent  NVARCHAR(500) NULL,
    blocked     BIT           NOT NULL DEFAULT 0,
    timestamp   DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- 15. RISK_SCORES
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE dbo.risk_scores (
    id            INT           IDENTITY(1,1) PRIMARY KEY,
    ip_address    NVARCHAR(45)  NOT NULL,
    score         FLOAT         NOT NULL,
    level         NVARCHAR(20)  NOT NULL,
    attack_type   NVARCHAR(80)  NULL,
    packet_count  INT           NOT NULL DEFAULT 0,
    calculated_at DATETIME2     NOT NULL DEFAULT GETUTCDATE()
);
GO

-- ─────────────────────────────────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────────────────────────────────
CREATE INDEX ix_users_username        ON dbo.users          (username);
CREATE INDEX ix_users_email           ON dbo.users          (email);
CREATE INDEX ix_user_roles_user_id    ON dbo.user_roles     (user_id);
CREATE INDEX ix_user_roles_role_id    ON dbo.user_roles     (role_id);
CREATE INDEX ix_login_history_user_id ON dbo.login_history  (user_id);
CREATE INDEX ix_login_history_ip      ON dbo.login_history  (ip_address);
CREATE INDEX ix_login_history_at      ON dbo.login_history  (login_at);
CREATE INDEX ix_audit_logs_timestamp  ON dbo.audit_logs     (timestamp);
CREATE INDEX ix_ioc_entries_type      ON dbo.ioc_entries    (ioc_type);
CREATE INDEX ix_ioc_entries_value     ON dbo.ioc_entries    (value);
CREATE INDEX ix_security_events_ip    ON dbo.security_events(ip_address);
CREATE INDEX ix_risk_scores_ip        ON dbo.risk_scores    (ip_address);
GO

-- ─────────────────────────────────────────────────────────────────
-- SEED: default roles
-- ─────────────────────────────────────────────────────────────────
INSERT INTO dbo.roles (name, description, level, is_system) VALUES
    ('viewer',  'Read-only access: dashboards and logs',           0, 1),
    ('analyst', 'SOC operations: cases, blocks, firewall, alerts', 1, 1),
    ('admin',   'Full access: settings, users, roles, audit',      2, 1);
GO


SELECT * FROM dbo.roles;
SELECT * FROM dbo.permissions;
SELECT * FROM dbo.role_permissions;
Select * From users;
