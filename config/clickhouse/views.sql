-- =====================================================================
-- ClickHouse · capa semántica de seguridad
-- ---------------------------------------------------------------------
-- Vistas que encapsulan la estructura física. Los paneles de
-- observabilidad consultan estas vistas, no las tablas: así el
-- modelo puede cambiar sin tocar los paneles, y las consultas
-- complexas viven en un único sitio.
--
-- Aplicar DESPUÉS de schema.sql:
--   clickhouse-client --multiquery < views.sql
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Eventos por minuto (base de todas las series temporales)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_eventos_por_minuto AS
SELECT
    toStartOfMinute(timestamp)                       AS time,
    service,
    count()                                         AS eventos,
    uniqExact(src_ip)                               AS ips,
    countIf(http_status >= 400)                     AS errores,
    countIf(level IN ('critical', 'high'))          AS eventos_criticos
FROM security.security_logs
GROUP BY time, service;

-- ---------------------------------------------------------------------
-- 2. Top IPs atacantes
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_top_ips_atacantes AS
SELECT
    src_ip,
    service,
    count()                                         AS eventos,
    countIf(http_status >= 400)                     AS errores,
    countIf(level IN ('critical', 'high'))          AS criticos,
    countIf(rule_id != '')                          AS con_regla,
    groupUniqArray(10)(uri)                         AS uris,
    min(timestamp)                                  AS primera_vez,
    max(timestamp)                                  AS ultima_vez
FROM security.security_logs
WHERE http_status >= 400 OR rule_id != ''
GROUP BY src_ip, service
ORDER BY errores DESC, criticos DESC;

-- ---------------------------------------------------------------------
-- 3. IPs baneadas (decisiones vigentes en el rango)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_ips_baneadas AS
SELECT
    source_ip                                      AS ip,
    scenario,
    source_country                                 AS pais,
    source_as_number                               AS asn,
    max(timestamp)                                 AS ban_desde,
    max(duration_seconds)                          AS duracion_s,
    count()                                        AS decisiones
FROM security.crowdsec_logs
WHERE action = 'ban' AND scenario != 'unknown'
GROUP BY source_ip, scenario, source_country, source_as_number;

-- ---------------------------------------------------------------------
-- 4. Bans por escenario
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_bans_por_escenario AS
SELECT
    scenario,
    count()                                         AS decisiones,
    uniqExact(source_ip)                            AS ips,
    max(timestamp)                                 AS ultimo,
    groupUniqArray(5)(source_country)              AS paises
FROM security.crowdsec_logs
WHERE action = 'ban' AND scenario != 'unknown'
GROUP BY scenario
ORDER BY decisiones DESC;

-- ---------------------------------------------------------------------
-- 5. Reglas del WAF que más disparan
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_reglas_waf AS
SELECT
    rule_id,
    rule_msg,
    rule_severity,
    groupUniqArray(5)(rule_tags)                   AS tags,
    count()                                         AS disparos,
    uniqExact(src_ip)                               AS ips,
    groupUniqArray(10)(uri)                        AS uris,
    max(timestamp)                                  AS ultimo
FROM security.security_logs
WHERE service = 'coraza' AND rule_id != ''
GROUP BY rule_id, rule_msg, rule_severity
ORDER BY disparos DESC;

-- ---------------------------------------------------------------------
-- 6. URIs más atacadas
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_uris_atacadas AS
SELECT
    uri,
    service,
    count()                                         AS peticiones,
    uniqExact(src_ip)                               AS ips,
    countIf(http_status = 403)                      AS bloqueadas_waf,
    countIf(http_status = 404)                      AS no_encontradas
FROM security.security_logs
WHERE uri != '' AND (http_status >= 400 OR rule_id != '')
GROUP BY uri, service
ORDER BY peticiones DESC;

-- ---------------------------------------------------------------------
-- 7. Recuento por país de origen
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_paises_atacantes AS
SELECT
    c.source_country                                AS pais,
    count()                                         AS decisiones,
    uniqExact(c.source_ip)                          AS ips,
    uniqExact(c.scenario)                           AS escenarios
FROM security.crowdsec_logs AS c
WHERE c.action = 'ban' AND c.scenario != 'unknown'
GROUP BY pais
ORDER BY decisiones DESC;

-- ---------------------------------------------------------------------
-- 8. Embudo de detección
-- ---------------------------------------------------------------------
-- El embudo completo: peticiones → errores → WAF → bloqueo → IPs.
-- Es el widget de nivel ejecutivo del panel SOC.
CREATE OR REPLACE VIEW security.v_embudo_deteccion AS
SELECT
    (SELECT count() FROM security.security_logs
      WHERE service = 'haproxy')                    AS peticiones,
    (SELECT count() FROM security.security_logs
      WHERE service = 'haproxy' AND http_status >= 400) AS errores,
    (SELECT count() FROM security.security_logs
      WHERE service = 'coraza')                     AS waf_hits,
    (SELECT count() FROM security.crowdsec_logs
      WHERE action = 'ban' AND scenario != 'unknown') AS bans,
    (SELECT uniqExact(source_ip) FROM security.crowdsec_logs
      WHERE action = 'ban' AND scenario != 'unknown') AS ips_baneadas;

-- ---------------------------------------------------------------------
-- 9. Eventos de runtime
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW security.v_falco_eventos AS
SELECT
    timestamp,
    host,
    container,
    rule,
    priority,
    source,
    output,
    tags,
    process,
    pid,
    src_ip
FROM security.falco_events;

-- ---------------------------------------------------------------------
-- 10. Salud de la ingesta
-- ---------------------------------------------------------------------
-- ¿Está llegando todo? Un salto de retraso en `retraso_s` significa
-- que el pipeline se ha parado o que el almacén no está recibiendo.
CREATE OR REPLACE VIEW security.v_salud_ingesta AS
SELECT
    service,
    max(timestamp)                                 AS ultimo_evento,
    dateDiff('second', max(timestamp), now())      AS retraso_s,
    countIf(timestamp > now() - INTERVAL 1 HOUR)    AS eventos_ultima_hora,
    countIf(timestamp > now() - INTERVAL 1 DAY)     AS eventos_ultimo_dia
FROM security.security_logs
GROUP BY service;
