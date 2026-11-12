-- =====================================================================
-- ClickHouse · esquema de la telemetría de seguridad
-- ---------------------------------------------------------------------
-- Esquema v2. Corrige tres defectos del esquema v1:
--
--   1. `rule_name` guardaba la línea de auditoría COMPLETA del CRS,
--      lo que producía 87.869 valores distintos en una columna que
--      debería ser un identificador de regla. Aquí se descompone en
--      rule_id / rule_msg / rule_severity / rule_tags.
--
--   2. `level` se derivaba del código de respuesta HTTP. En fase de
--      petición no hay respuesta, así que una detección LFI de
--      severidad "critical" se clasificaba como "info". Aquí el nivel
--      sale de la severidad de la regla.
--
--   3. `src_ip` era texto plano y en algunos casos guardaba
--      "ip:puerto", lo que obligaba a las consultas a hacer
--      splitByChar. Aquí es IPv4 tipada.
--
-- Aplicar:
--   clickhouse-client --multiquery < schema.sql
-- =====================================================================

CREATE DATABASE IF NOT EXISTS security;

-- ---------------------------------------------------------------------
-- 1. Eventos del perímetro
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.security_logs
(
    timestamp      DateTime64(3, 'UTC')          CODEC(Delta, ZSTD(1)),

    -- Identidad del evento
    host           LowCardinality(String)        CODEC(ZSTD(1)),
    service        LowCardinality(String)        CODEC(ZSTD(1)),
    event_type     LowCardinality(String)        CODEC(ZSTD(1)),

    -- Nivel: derivado de la severidad de la regla, NO del código HTTP
    level          LowCardinality(String)        CODEC(ZSTD(1)),

    -- Origen
    src_ip         IPv4,
    src_country    LowCardinality(String)        DEFAULT '' CODEC(ZSTD(1)),
    src_as_number  UInt32                       DEFAULT 0,
    src_as_name    String                       DEFAULT '',

    -- Capa web
    http_method    LowCardinality(String)        DEFAULT '' CODEC(ZSTD(1)),
    uri            String                       DEFAULT '' CODEC(ZSTD(1)),
    http_status    UInt16                       DEFAULT 0,

    -- Regla que disparó el evento (v2: campos separados)
    rule_id        String                       DEFAULT '',
    rule_msg       String                       DEFAULT '',
    rule_severity  UInt8                        DEFAULT 0,
    rule_tags      Array(String)                DEFAULT [],

    auth_user      String                       DEFAULT '',

    -- Evento original, íntegro: auditoría forense
    message        String,
    raw_json       String                       CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (service, src_ip, timestamp)
TTL toDateTime(timestamp) + INTERVAL 3 MONTH
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------
-- 2. Decisiones de bloqueo
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.crowdsec_logs
(
    timestamp        DateTime DEFAULT now(),
    scenario         LowCardinality(String),
    source_ip        IPv4,
    source_country   LowCardinality(String),
    source_as_number UInt32,
    source_as_name   String,
    action           LowCardinality(String),
    duration_seconds UInt32,
    origin           LowCardinality(String),
    log_type         LowCardinality(String),
    raw_message      String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, scenario, source_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------
-- 3. Eventos de runtime (eBPF) — pendiente de despliegue
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.falco_events
(
    timestamp      DateTime64(3, 'UTC')          CODEC(Delta, ZSTD(1)),
    host           LowCardinality(String)        CODEC(ZSTD(1)),
    container      String                       DEFAULT '',
    rule           String                       DEFAULT '',
    priority       LowCardinality(String)        DEFAULT '',
    source         LowCardinality(String)        DEFAULT '',
    output         String                       DEFAULT '',
    tags           Array(String)                DEFAULT [],
    process        String                       DEFAULT '',
    pid            UInt32                       DEFAULT 0,
    src_ip         IPv4                         DEFAULT '0.0.0.0',
    message        String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (rule, timestamp)
TTL toDateTime(timestamp) + INTERVAL 3 MONTH
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------
-- 4. Diccionario de geolocalización
-- ---------------------------------------------------------------------
-- 3,7 M de rangos. Se usa como DICTIONARY (IP_TRIE) en vez de un
-- LEFT JOIN: la búsqueda se resuelve en el índice, no se recalcula
-- en cada consulta.
--
-- La tabla de origen se puebla con el dataset público de rangos:
--   CREATE TABLE security.geoip_ranges (cidr String, country_code String, country_name String) ENGINE = MergeTree ORDER BY cidr;
--   INSERT INTO security.geoip_ranges FORMAT CSVWithNames < geoip_ranges.csv
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.geoip_ranges
(
    cidr         String,
    country_code String,
    country_name String
)
ENGINE = MergeTree
ORDER BY cidr
SETTINGS index_granularity = 8192;

CREATE DICTIONARY IF NOT EXISTS security.geoip_dict
(
    cidr         String,
    country_code String,
    country_name String
)
PRIMARY KEY cidr
SOURCE(CLICKHOUSE(
    USER 'dict_reader'
    PASSWORD '${DICT_READER_PASSWORD}'
    DB 'security'
    TABLE 'geoip_ranges'
))
LIFETIME(MIN 3600 MAX 7200)
LAYOUT(IP_TRIE());

-- ---------------------------------------------------------------------
-- 5. Usuarios
-- ---------------------------------------------------------------------
-- El usuario de ingesta tiene INSERT y NADA MÁS: quien escribe no
-- puede leer lo que otros escribieron.
--
-- La credencial se inyecta desde el entorno. En un despliegue real:
--   clickhouse-client --query "ALTER USER security_ingest IDENTIFIED WITH sha256_password BY '<NUEVO>'"
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS security_ingest
    IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_PASSWORD}';

GRANT INSERT ON security.security_logs TO security_ingest;
GRANT INSERT ON security.crowdsec_logs TO security_ingest;
GRANT INSERT ON security.falco_events TO security_ingest;

-- Usuario de solo lectura para los paneles.
CREATE USER IF NOT EXISTS security_ro
    IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_RO_PASSWORD}';

GRANT SELECT ON security.* TO security_ro;
