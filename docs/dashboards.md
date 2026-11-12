# El panel SOC

El panel de detección principal: **18 widgets** organizados en **6 secciones**
que siguen el **ciclo de vida completo de un ataque**, desde el reconocimiento
previo hasta la reincidencia posterior al bloqueo.

Tres variables multi-select permiten filtrar todo el panel por **IP de
atacante**, **país** y **escenario de detección**, con opción `All`.

| Variable | Origen de los valores | Multi | All |
|---|---|:--:|:--:|
| `$ip` | `SELECT DISTINCT src_ip FROM security.security_logs` | ✅ | ✅ |
| `$pais` | `SELECT DISTINCT source_country FROM security.crowdsec_logs` | ✅ | ✅ |
| `$escenario` | `SELECT DISTINCT scenario FROM security.crowdsec_logs` | ✅ | ✅ |

---

## 1. Estructura del panel

| # | Sección | Widgets | Qué responde |
|---|---|---|---|
| 1 | Vista general y métricas globales | 3 | ¿Cuánto está pasando y a qué escala? |
| 2 | Línea de tiempo del ataque | 3 | ¿Cuándo y desde dónde? |
| 3 | Fase previa: reconocimiento y falsos negativos | 2 | ¿Qué se estaba explorando antes de ser detectado? |
| 4 | Fase de detección: origen del ataque | 2 | ¿Cómo se clasificó y de dónde viene? |
| 5 | Fase posterior: efectividad del bloqueo | 1 | ¿Funcionó el ban? |
| 6 | Investigación detallada | 1 | ¿Qué ocurrió exactamente? |

### Sección 1 · Vista general

- **Total de decisiones de CrowdSec** en el rango.
- **IPs únicas sancionadas**.
- **Top país atacante**.

Las tres son globales (no filtered por las variables), deliberadamente: son
los tres números de nivel ejecutivo que se miran primero.

### Sección 2 · Línea de tiempo

- **Mapa geográfico** de las IPs detectadas, con su país.
- **Tráfico sospechoso frente a bloqueos activos**: serie temporal que
  superpone el volumen de peticiones con error (`http_status >= 400`) y el
  número de bloqueos de CrowdSec en el mismo minuto.
- **Auditoría de IPs atacantes y bloqueos**: tabla con el detalle por IP.

### Sección 3 · Fase previa

- **Top URIs exploradas**: qué rutas se están probando.
- **Falsos negativos**: IPs que generan actividad sospechosa pero que
  **CrowdSec no ha registrado como atacantes**. Es el widget más valioso del
  panel: señala huecos de cobertura.

### Sección 4 · Fase de detección

- **Tipos de escenario de ataque**: qué regla se está disparando.
- **Top países de origen**.

### Sección 5 · Fase posterior

- **Reincidencia**: tráfico que **siguió llegando después** del bloqueo.
  Mide si el ban fue efectivo y si el atacante tenía capacidad de evasión.

### Sección 6 · Investigación

- **Inspector de logs** con los campos del evento (fecha, IP, servicio, método,
  URI, estado) y los mismos filtros globales.

---

## 2. Las consultas que lo sostienen

### 2.1 Tráfico sospechoso frente a bloqueos

```sql
SELECT
    toStartOfInterval(COALESCE(s.timestamp, c.timestamp), toIntervalMinute(1)) AS time,
    sum(CASE WHEN s.http_status >= 400 THEN 1 ELSE 0 END) AS "Peticiones Errores 4xx/5xx",
    sum(CASE WHEN c.source_ip != toIPv4('0.0.0.0') THEN 1 ELSE 0 END) AS "Bloqueos CrowdSec"
FROM security.security_logs AS s
FULL OUTER JOIN security.crowdsec_logs AS c
    ON toIPv4OrDefault(splitByChar(':', s.src_ip)[1]) = c.source_ip
    AND toStartOfInterval(s.timestamp, toIntervalMinute(1))
     = toStartOfInterval(c.timestamp, toIntervalMinute(1))
WHERE ($__timeFilter(s.timestamp) OR $__timeFilter(c.timestamp))
  AND ('$__all' IN (${ip:singlequote})
       OR match(splitByChar(':', s.src_ip)[1], concat('^(', '${ip:pipe}', ')$'))
       OR match(IPv4NumToString(c.source_ip), concat('^(', '${ip:pipe}', ')$')))
  AND ('$__all' IN (${pais:singlequote})
       OR match(c.source_country, concat('^(', '${pais:pipe}', ')$')))
  AND ('$__all' IN (${escenario:singlequote})
       OR match(c.scenario, concat('^(', '${escenario:pipe}', ')$')))
GROUP BY time
ORDER BY time ASC
```

**Tres detalles que importan:**

1. **`FULL OUTER JOIN`** en lugar de `LEFT JOIN`: se necesitan tanto las
   filas con tráfico sospechoso como las que sólo tienen bloqueo, y el
   `COALESCE` de las dos columnas de tiempo las une por minuto.
2. **`splitByChar(':', s.src_ip)[1]`**: el campo de IP de origen guarda
   `ip:puerto` para el tráfico del proxy, así que hay que separar la IP.
   Es una de las razones por las que el esquema v2 propone una columna IPv4
   dedicada.
3. **`concat('^(', '${ip:pipe}', ')$')`**: con la variable en modo `pipe` se
   construye una expresión regular que acepta **varios** valores separados
   por comas. Con `singlequote` se comprueba la pertenencia al conjunto `All`.
   Es el patrón correcto para variables multi-select en filtros regex.

### 2.2 Falsos negativos

```sql
SELECT
    s.src_ip      AS ip_sospechosa,
    s.service     AS service,
    count()       AS intentos_fallidos,
    groupArrayDistinct(s.http_status) AS estados
FROM security.security_logs AS s
LEFT JOIN security.crowdsec_logs AS c
    ON toIPv4OrDefault(splitByChar(':', s.src_ip)[1]) = c.source_ip
WHERE $__timeFilter(s.timestamp)
  AND (s.http_status IN (401, 403) OR s.rule_name != '')
  AND c.source_ip = toIPv4('0.0.0.0')
  AND ('$__all' IN (${ip:singlequote})
       OR match(splitByChar(':', s.src_ip)[1], concat('^(', '${ip:pipe}', ')$')))
GROUP BY ip_sospechosa, s.service
HAVING intentos_fallidos > 15
ORDER BY intentos_fallidos DESC
LIMIT 10
```

**La idea:** una IP que acumula más de 15 intentos fallidos y que **no
aparece** en el registro de decisiones de CrowdSec es un hueco de cobertura.
O bien la regla que debería detectarla no está desplegada, o bien su umbral
es demasiado alto, o bien hay un tipo de ataque que ninguna regla cubre.

El `LEFT JOIN` con la condición `c.source_ip = toIPv4('0.0.0.0')` es un
truco para quedarse **sólo con las filas sin match** en el join: si hubiera
match, `c.source_ip` sería la IP real y no `0.0.0.0`.

### 2.3 Reincidencia posterior al bloqueo

```sql
SELECT
    IPv4NumToString(c.source_ip) AS ip_bloqueada,
    c.scenario      AS motivo_bloqueo,
    c.timestamp     AS fecha_bloqueo,
    count(s.timestamp) AS intentos_posteriores_al_bloqueo
FROM security.crowdsec_logs AS c
INNER JOIN security.security_logs AS s
    ON IPv4NumToString(c.source_ip) = splitByChar(':', s.src_ip)[1]
WHERE $__timeFilter(s.timestamp)
  AND s.timestamp > c.timestamp
  AND ('$__all' IN (${ip:singlequote})
       OR match(IPv4NumToString(c.source_ip), concat('^(', '${ip:pipe}', ')$')))
  AND ('$__all' IN (${pais:singlequote})
       OR match(c.source_country, concat('^(', '${pais:pipe}', ')$')))
  AND ('$__all' IN (${escenario:singlequote})
       OR match(c.scenario, concat('^(', '${escenario:pipe}', ')$')))
GROUP BY ip_bloqueada, motivo_bloqueo, fecha_bloqueo
ORDER BY intentos_posteriores_al_bloqueo DESC
LIMIT 15
```

**Qué mide:** el tráfico que siguió llegando **después** de que la IP fuera
baneada. Si el valor es cero, el ban fue eficaz. Si es alto, hay tres
explicaciones posibles, y el panel no las distingue por sí solo:

1. El tráfico es **posterior a la expiración** del ban (la duración por
   defecto de las reglas es de 4 h, con renewal).
2. El tráfico llegó por una **ruta que no pasa por el host perimetral**.
3. El bouncer no pudo aplicar el ban (set de nftables lleno, reglas no
   sincronizadas).

Esta distinción es exactamente la que justifica que el histórico de
decisiones se guarde **aparte** del histórico de tráfico: sin él, un `DROP`
y una petición que nunca llegó serían indistinguibles.

---

## 3. El panel SOC como pieza de un conjunto

El panel no vive solo. En la instancia de observabilidad hay 9 paneles en
total:

| Panel | Origen de los datos |
|---|---|
| **SOC · Ciclo de vida del ataque** | ClickHouse (`security.*`) |
| CrowdSec Metrics | Prometheus (`cs_*`) |
| CrowdSec Firewall Bouncer | Prometheus (métricas del bouncer) |
| Node Exporter Full | Prometheus |
| cAdvisor | Prometheus |
| Proxmox / Proxmox Backup Server | Prometheus (exporters de Proxmox) |
| Errores de ingesta | Prometheus (métricas del pipeline) |

El panel SOC es el único que consulta **ClickHouse**; el resto son métricas
de Prometheus. La separación es intencionada: las métricas dicen "está
fallando", el panel SOC dice "qué ha pasado".

---

## 4. Limitaciones conocidas

| Limitación | Origen | Mitigación prevista |
|---|---|---|
| El campo de IP incluye `:puerto` | Esquema v1 | Columna `IPv4` dedicada en el esquema v2 |
| El nivel se derivaba del código HTTP | Esquema v1 | `level` derivado de la severidad de la regla en v2 |
| `rule_name` contenía la línea de auditoría completa | Esquema v1 | Campos separados `rule_id`/`rule_msg`/`rule_severity`/`rule_tags` en v2 |
| El panel consulta las tablas, no la capa semántica | Diseño | Las vistas `v_*` de [`config/clickhouse/views.sql`](../config/clickhouse/views.sql) permiten encapsular estas consultas |
| La reincidencia no distingue expiración de fallo de bouncer | Lógica | El histórico de decisiones incluye la duración del ban; falta correlacionarla |
