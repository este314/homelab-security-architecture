# Runbook

Procedimientos de operación y mantenimiento del entorno.

> [!WARNING]
> **Los comandos de este documento llevan valores de ejemplo**
> (`192.168.10.10`, `perimeter-01`, `CHANGE_ME`). Sustituye por los valores
> reales de tu despliegue antes de ejecutar nada.

---

## 1. Estado de los servicios

```bash
# Perímetro
systemctl status haproxy suricata coraza-spoa vector crowdsec-firewall-bouncer

# Bus de eventos
docker ps --filter name=kafka --filter name=vector-aggregator
docker logs --tail 50 vector-aggregator

# Inteligencia
systemctl status crowdsec vector
cscli status

# Datos
systemctl status clickhouse-server
```

---

## 2. Diagnóstico

### 2.1 ¿Llega tráfico al almacén?

```sql
-- ¿Hay eventos en los últimos 15 minutos?
SELECT count() FROM security.security_logs
WHERE timestamp > now() - INTERVAL 15 MINUTE;

-- ¿Por servicio?
SELECT service, count() FROM security.security_logs
WHERE timestamp > now() - INTERVAL 15 MINUTE GROUP BY service;

-- ¿Hay lag en la ingesta? (edad del último evento por servicio)
SELECT service, max(timestamp), now() - max(timestamp) AS retraso
FROM security.security_logs GROUP BY service;
```

Si el retraso es alto, el problema está entre el perímetro y ClickHouse. El
siguiente paso es mirar el bus:

```bash
docker exec kafka kafka-topics --bootstrap-server localhost:9092 \
  --describe --topic security-logs-haproxy
```

Un `consumer group` con el offset rezagado confirma que el agregador no está
consumiendo; offsets en 0 con el topic vacío indican que el edge no publica.

### 2.2 ¿CrowdSec está detectando?

```bash
cscli metrics                      # acquisition y buckets
cscli decisions list               # decisiones activas
cscli alerts list                  # alertas sin bucket
cscli bouncers list                # estado y último pull de cada bouncer
```

| Síntoma | Causa probable | Acción |
|---|---|---|
| `Lines unparsed` sube | El formato del log de origen cambió | Actualizar el `remap` de Vector |
| Un bucket aparece con `Overflows` alto | Capacidad insuficiente para el volumen | Revisar `capacity` / `leakspeed` de la regla |
| Ningún bouncer aparece en `Last API pull` | Bouncer desconectado o key revocada | `cscli bouncers list`, reiniciar el bouncer |
| Decisiones sin `ban` | La regla no tiene `remediation: true` | Revisar las etiquetas del escenario |

### 2.3 ¿El bloqueo está aplicado?

```bash
# Estado real de las reglas en el host perimetral
nft list table crowdsec
nft list set crowdsec-blacklists | head -30

# Decisiones que el LAPI cree activas
cscli decisions list
```

Si el set está vacío pero hay decisiones activas, el bouncer no está
sincronizando: revisar su log y confirmar la conectividad con el LAPI.

### 2.4 El WAF no bloquea lo que debería

```bash
# Log de auditoría del WAF: qué regla disparó
grep -oE '\[id "[0-9]+"\].*\[msg "[^"]+"\]' /var/log/coraza/audit.log | tail -20

# Acción devuelta al proxy
grep 'X-WAF-Action' /var/log/haproxy.log | tail -10
```

El patrón habitual de un falso positivo:

1. La regla CRS que dispara se identifica en el audit log por su `[id]`.
2. Se localiza la familia de la regla (`OWASP_CRS/ATTACK-SQLI`, etc.).
3. Se añade una exclusión **acotada por objetivo** (`ARGS`, `ARGS_NAMES`) en
   la regla de excepción, nunca se desactiva la regla entera.

---

## 3. Mantenimiento

### 3.1 Rotación de credenciales

Procedimiento general, válido para las tres credenciales del entorno. **El
principio es siempre el mismo: cambiar primero en el destino, después en el
consumidor, y verificar antes de destruir el valor antiguo.**

#### Credencial de ingesta (ClickHouse)

```sql
-- 1. Generar y aplicar el nuevo valor en el almacén
ALTER USER security_ingest IDENTIFIED WITH sha256_password BY '<NUEVO>';

-- 2. Actualizar las credenciales en la configuración del agregador
#   (2 secciones: clickhouse_sink y clickhouse_crowdsec_sink)
#   password = "<NUEVO>"

-- 3. Reiniciar el agregador (no recarga credenciales en caliente)
docker restart vector-aggregator

-- 4. VERIFICAR antes de continuar
docker logs --tail 20 vector-aggregator | grep -i error
```

**Ventana de riesgo:** la ingesta se detiene mientras el agregador no
reinicia (~5 s). Si el password no coincide exactamente con el del
almacén, el error aparece en el log del agregador y **no** hay pérdida de
datos: Kafka los retiene.

#### Credencial del bouncer (CrowdSec)

```bash
# 1. Crear el bouncer NUEVO sin tocar el existente
cscli bouncers add firewall-bouncer-new

# 2. Actualizar la clave en la configuración del bouncer
#    /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
#    api_key: "<NUEVA>"

# 3. Reiniciar y VERIFICAR la conectividad
systemctl restart crowdsec-firewall-bouncer
cscli bouncers list          # debe mostrar el pull reciente

# 4. Sólo entonces, retirar el anterior
cscli bouncers delete firewall-bouncer-old
```

**Ventana de riesgo:** con los dos bouncers activos, una IP puede estar
bloqueada en dos sitios. Es inocuo. El orden inverso (borrar primero) deja
una ventana sin bloqueo.

#### Secreto de excepción del WAF

Este es el caso con dependencia externa (el cliente legítimo que consume la
excepción), así que admite una **ventana dual**:

```apache
# 1. Aceptar el valor antiguo Y el nuevo durante el periodo de transición
SecRule REQUEST_HEADERS:X-Ingest-Token "@rx ^(TOKEN_VIEJO|TOKEN_NUEVO)$" \
    "id:1000104,phase:2,pass,nolog,..."
```

```bash
# 2. Reiniciar el motor
systemctl restart coraza-spoa

# 3. Actualizar el cliente legítimo (fuera de este entorno)
#    y VERIFICAR que las peticiones siguen entrando

# 4. Una vez confirmado, dejar sólo el valor nuevo
SecRule REQUEST_HEADERS:X-Ingest-Token "@streq TOKEN_NUEVO" \
    "id:1000104,phase:2,pass,nolog,..."

systemctl restart coraza-spoa
```

**Ventana de riesgo:** con la ventana dual, el secreto antiguo sigue siendo
válido. Hay que fijar una fecha de cierre.

#### Grafana

El usuario de lectura del almacén analítico debe ser de **solo lectura**:

```sql
CREATE USER IF NOT EXISTS sentinel_ro IDENTIFIED WITH sha256_password BY '<NUEVO>';
GRANT SELECT ON security.* TO sentinel_ro;
```

---

### 3.2 Actualización del conjunto de reglas

```bash
# Actualizar el hub de CrowdSec
cscli hub update

# Listar what's new antes de aplicarlo
cscli hub list --all

# Aplicar
cscli hub upgrade

# Recargar escenarios (no reinicia el LAPI)
systemctl reload crowdsec
```

**Precaución.** Una actualización del hub puede:

- Añadir reglas que generen falsos positivos sobre tráfico legítimo.
- Cambiar los parámetros de reglas existentes (capacidad, ventana).

Después de actualizar, hay que **revisar las métricas de buckets** durante un
ciclo de tráfico completo antes de dar por buena la versión.

---

### 3.3 Mantenimiento de ClickHouse

```sql
-- Tamaño por tabla
SELECT name, formatReadableSize(total_bytes) AS disco,
       formatReadableQuantity(total_rows) AS filas
FROM system.tables WHERE database = 'security' ORDER BY total_bytes DESC;

-- Particiones disponibles (para purgar un mes entero)
SELECT partition, rows, formatReadableSize(bytes_on_disk)
FROM system.parts WHERE database='security' AND table='security_logs'
  AND active GROUP BY partition, rows, bytes_on_disk ORDER BY partition;
```

```bash
# Purga inmediata de una partición (no espera al merge de TTL)
clickhouse-client --query "ALTER TABLE security.security_logs DROP PARTITION '202608'"
```

El `TTL` purga en segundo plano durante las fusiones. Si hay que liberar
espacio de inmediato, `DROP PARTITION` es instantáneo y `OPTIMIZE TABLE ...
FINAL` compacta.

---

### 3.4 Mantenimiento de Kafka

```bash
# Retención actual de los topics
docker exec kafka kafka-configs --bootstrap-server localhost:9092 --describe \
  --entity-type topics --entity-name 'security-logs-.*'

# Tamaño por topic
docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list \
  | while read t; do
      echo "$t: $(docker exec kafka kafka-log-dirs --bootstrap-server localhost:9092 \
        --describe --topic-log-dirs --topic "$t" 2>/dev/null | wc -l) particiones"
    done
```

**No purgar topics sin consultar la retención**: el topic es la única copia
de los eventos que el filtro de edge descarta. Si se necesita depurar un
topic, hacerlo **después** de confirmar que la retención del almacén analítico
ya cubre el periodo.

---

### 3.5 Actualización de las reglas del IDS

```bash
suricata-update                     # descarga el conjunto más reciente
suricata-update -s <fichero>        # un conjunto concreto
suricata-update -T                  # sólo test, no aplica
systemctl reload suricata
```

**Después de actualizar, hay que revisar la lista de reglas filtradas en el
edge** (ver [ADR-003](adr/003-filtrado-en-el-edge.md)): si el conjunto
cambia, la lista de reglas de estado de stream que se descartan debe
revisarse. Una regla nueva con el mismo patrón de nombre no se filtraría.

---

## 4. Recuperación

### 4.1 El bouncer ha perdido el estado

```bash
systemctl restart crowdsec-firewall-bouncer
nft list set crowdsec-blacklists | wc -l
```

El bouncer repuebla el set en el siguiente refresco (≤ 10 s). Si el set
sigue vacío y hay decisiones activas, el problema es de conectividad con el
LAPI, no de estado.

### 4.2 ClickHouse no arranca

```bash
systemctl status clickhouse-server
journalctl -u clickhouse-server -n 100 --no-pager
tail -50 /var/log/clickhouse-server/clickhouse-server.err.log
```

Causas frecuentes: disco lleno (el `TTL` no ha purgado y el historial
creció), corrupción de una partición, o una configuración con un cambio de
formato.

```bash
# Verificar y reparar una tabla concreta
clickhouse-client --query "CHECK TABLE security.security_logs"
```

### 4.3 El LAPI ha perdido su base

El LAPI guarda el estado en su base local (SQLite). Si se pierde:

```bash
# Reinstalar los escenarios
cscli hub update && cscli hub upgrade

# Volver a registrar el bouncer (genera una key nueva)
cscli bouncers add firewall-bouncer-new
```

**Lo que se pierde:** el histórico de decisiones (los eventos brutos siguen en
ClickHouse, así que se puede reconstruir el análisis). **Lo que no se pierde:**
la capacidad de seguir detectando, una vez repoblados los escenarios.

---

## 5. Verificaciones periódicas

| Periodicidad | Comprobación | Criterio de alarma |
|---|---|---|
| Diaria | Ingesta viva | Eventos en los últimos 15 min > 0 |
| Diaria | `cs_node_hits_ko_total` | Cualquier incremento (el parser no entiende el formato) |
| Diaria | Decisiones activas | Variación abrupta respecto a la media |
| Semanal | Crecimiento del almacén | Por encima del growth con TTL aplicado |
| Semanal | Fallos de parseo de Suricata | `alert.signature` vacía en eventos con `event_type=alert` |
| Mensual | Copia de seguridad del almacén | Restauración verificada en un entorno limpio |
| Mensual | Revisión de la lista de reglas filtradas | Coincide con el conjunto de reglas activo |
| Trimestral | Rotación de credenciales | Procedimiento de la sección 3.1 |

---

## 6. Checklist de puesta en marcha

```bash
# 1. Configuración presente y sin valores hardcodeados
grep -rn "password\|api_key\|token" config/ | grep -v CHANGE_ME | grep -v '\$\{'

# 2. Vector valida su configuración
vector validate --config /etc/vector/vector.toml

# 3. Prometheus valida la suya
promtool check config /etc/prometheus/prometheus.yml

# 4. ClickHouse valida el DDL
clickhouse-client --query "EXPLAIN SYNTAX SELECT 1"

# 5. CrowdSec ve sus escenarios
cscli scenarios list | wc -l

# 6. El bouncer se sincroniza
cscli bouncers list
```
