# Arquitectura

Documento de referencia del entorno. El [`README.md`](../README.md) resume los
pilares; aquí se desarrolla el detalle: componentes, flujos, decisiones y números.

---

## 1. Principios de diseño

1. **Un solo camino de ingesta.** Todo evento —sea del perímetro, de la
   detección o del runtime— entra al bus por el mismo topic y sale por el
   mismo consumidor. Añadir una fuente nueva no debe crear un segundo pipeline.
2. **Filtrar donde la información es más barata.** Descartar ruido en el
   origen (Vector) antes de escribirlo cuesta CPU de un nodo; hacerlo en el
   destino cuesta disco, CPU y red.
3. **El estado de la decisión vive en un solo sitio.** El LAPI de CrowdSec
   es la autoridad; el bouncer es un ejecutor sin estado. Reconstruir el
   perímetro de bloqueo desde cero es una operación de un minuto.
4. **Nada de agentes pesados por nodo.** El coste de detección se paga una vez,
   en el cerebro, no en cada host.
5. **El panel se apoya en la capa semántica, no en las tablas.** Las consultas
   de Grafana no conocen la estructura física: la encapsulan las vistas.

---

## 2. Inventario de componentes

### Perímetro — `perimeter-01`

| Componente | Puerto / socket | Función |
|---|---|---|
| HAProxy 2.2.9 | `443`, `80` | Terminación TLS, enrutado por `Host`, IP real de cliente |
| Coraza SPOA | SPOE `:9000` | WAF L7 con OWASP CRS 4.30 |
| Suricata 6.0.1 | captura + `eve.json` | IDS/IPS con reglas *Emerging Threats* |
| Vector (edge) 0.38.0 | — | Normaliza y publica en Kafka |
| firewall-bouncer 0.0.36 | — | Aplica las decisiones con nftables/iptables |

El WAF **no es un proxy más**: se integra en HAProxy mediante el protocolo
SPOE. HAProxy delega la evaluación y recibe de vuelta la acción, de modo que
el camino de la petición no añade un salto ni un nuevo punto de terminación TLS.

### Bus de eventos — `pipeline-01`

| Componente | Función |
|---|---|
| Kafka 7.6.0 (KRaft, un broker) | Bus de eventos. Un topic por servicio de origen |
| Vector (aggregator) 0.57.0 | Único escritor hacia ClickHouse. Batching de 5.000 eventos |

Los topics siguen el patrón `security-logs-<servicio>`, lo que permite a los
consumidores suscribirse por patrón (`^security-logs-.*`) en lugar de
enumerar topics.

### Inteligencia — `intel-01`

| Componente | Función |
|---|---|
| CrowdSec 1.4.6 (LAPI) | Adquisición, parseo, buckets, escenarios, decisiones |
| Vector 0.38.0 | Traduce el topic de Kafka al formato de log que espera la adquisición de CrowdSec |

El Vector de este nodo **re-escribe**: el LAPI consume ficheros de log en
línea, no mensajes de Kafka. El Vector escribe en
`/var/log/crowdsec-pipeline/<servicio>.log` y CrowdSec lo adquiere desde ahí.

### Datos — `store-01`

| Componente | Función |
|---|---|
| ClickHouse 25.5.1 | Histórico columnar, TTL, capa semántica |
| `security.geoip_dict` | Diccionario `IP_TRIE` con 3,7 M de rangos para enriquecer por país |

### Observabilidad — `obs-01`

| Componente | Función |
|---|---|
| Prometheus 3.13.1 | 21 targets vía Consul SD, 823 series |
| Grafana 13.1 | 9 paneles, incluido el panel SOC de 18 widgets |
| node_exporter ×10, cAdvisor ×3 | Métricas de host y de contenedor |

---

## 3. Flujos de datos

### 3.1 Evento del perímetro → histórico

```text
fichero de log  →  Vector edge  →  parseo VRL  →  topic security-logs-<svc>
                →  Vector aggregator  →  ClickHouse security.security_logs
```

El Vector edge hace el trabajo pesado de **normalización**: cada fuente tiene
su formato y todos acaban en el mismo esquema. La ventaja es que el ClickHouse
no necesita saber nada del formato original, y que añadir un servicio nuevo
es añadir un `remap`, no tocar el esquema.

El aggregator es deliberadamente **tonto**: parsea lo que ya viene normalizado
y escribe. Toda la lógica de negocio está en el edge.

### 3.2 Evento del perímetro → decisión → bloqueo

```text
topic security-logs-<svc>  →  Vector intel  →  /var/log/crowdsec-pipeline/<svc>.log
                           →  adquisición CrowdSec  →  parser  →  bucket
                           →  escenario  →  decisión (ban)
                           →  LAPI  →  bouncer  →  set nftables  →  DROP
```

**La latencia está dominada por el refresco del bouncer**, que es de 10 s. El
resto del proceso (parseo, bucket, decisión) tarda del orden de milisegundos.

### 3.3 Métricas

Prometheus no lee logs: scrapea exporters. CrowdSec expone su propio
endpoint de métricas (`cs_alerts`, `cs_active_decisions`, `cs_bucket_*`) y el
bouncer expone las suyas. El detalle por evento vive en ClickHouse.

> **Regla de no duplicación:** si un dato existe como métrica, se consulta
> como métrica; si existe como evento, se consulta como evento. Duplicar
> significa mantener dos caminos de verdad para el mismo hecho.

---

## 4. Optimización: el 79,5 % de ruido

### El síntoma

El histórico de 90 días contiene 9.101.705 filas. La distribución real:

| Clase | Filas | % |
|---|---:|---:|
| Ruido (3 reglas de estado TCP) | 7.237.981 | **79,5 %** |
| Util | 1.863.724 | 20,5 % |

Las tres reglas son:

```text
SURICATA STREAM Packet with invalid ack
SURICATA STREAM ESTABLISHED invalid ack
SURICATA STREAM ESTABLISHED packet out of window
```

Describen **anomalías de estado TCP**, no ataques: se disparan enResultado de
retransmisiones, segmentación fuera de ventana o clientes que renegocian. El
volumen es brutal en días de tráfico alto:

| Día | Filas | Composición |
|---|---:|---|
| 16-oct | 1.735.503 | 99,4 % ruido |
| 30-oct | 1.789.983 | 99,6 % ruido |
| Media de un día normal | 5.000 – 50.000 | ~20 % ruido |

### La causa

El filtro del edge sólo descartaba los eventos que **no** eran `event_type ==
"alert"`. Las tres reglas problemáticas **sí** son alertas, pero de severidad
3 (baja), que es exactamente el nivel que el esquema no distingue.

### La solución

Dos filtros encadenados, ambos en el edge:

1. **Por regla.** Lista explícita de reglas de estado de stream que se
   descartan: describen el transporte, no la intención del atacante.
2. **Por severidad.** Sólo pasan a ClickHouse las alertas de severidad ≥ 2.
   El nivel de transporte (severidad 3) se conserva en el topic de Kafka, que
   es donde se consulta para diagnóstico fino, no en el histórico analítico.

**Resultado esperado:** el histórico baja de 9,1 M a ~1,9 M de filas con la
misma capacidad de detección, y el pico diario de 1,79 M desaparece.

### El error de esquema que escondía el problema

El campo `rule_name` guardaba **la línea de auditoría completa del CRS** (con
el fichero, la línea, el id, el mensaje, la severidad, las etiquetas y el
`unique_id`), lo que producía **87.869 valores distintos** en una columna que
debería ser un identificador de regla. Dos efectos:

- La columna no era utilizable para agrupar (`GROUP BY rule_name`iba a
  producir decenas de miles de grupos).
- El `level` se derivaba del **código de respuesta HTTP**, de modo que una
  detección LFI de severidad *critical* arriving en fase de request (donde no
  hay respuesta todavía) se clasificaba como `info`.

El esquema v2 de [`config/clickhouse/schema.sql`](../config/clickhouse/schema.sql)
corrige ambos: campos separados `rule_id`, `rule_msg`, `rule_severity` y
`rule_tags`, y un `level` derivado de la severidad real de la regla.

---

## 5. Esquema de datos

### `security.security_logs`

Una fila por evento de log, normalizada. Clave de ordenación por servicio e
IP de origen (que es como se consulta), particionado por mes y con TTL de
3 meses.

Campos clave y su origen:

| Campo | Origen | Nota |
|---|---|---|
| `timestamp` | Vector | Always generated at ingest |
| `service` | Vector | `haproxy`, `suricata`, `coraza`, `apache` |
| `event_type` | Vector | `access`, `alert`, `waf_rule` |
| `level` | Vector | Derivado de la **severidad de la regla**, no del HTTP status |
| `src_ip` | Vector | IP de origen |
| `http_method` / `uri` / `http_status` | Vector | Solo para tráfico web |
| `rule_id` / `rule_msg` / `rule_severity` / `rule_tags` | Vector | **v2**: campos separados |
| `raw_json` | Vector | Evento original, para auditoría forense |

### `security.crowdsec_logs`

Una fila por decisión: escenario, IP, país, ASN, acción, duración, origen.

### `security.falco_events` (v2, pendiente de despliegue)

Una fila por evento de runtime: regla, prioridad, salida, proceso, contenedor.

### Capa semántica

Diez vistas que encapsulan la estructura física y que los paneles de Grafana
consumen. Ver [`config/clickhouse/views.sql`](../config/clickhouse/views.sql).

---

## 6. Topología física

| Nodo | Rol | Servicios |
|---|---|---|
| `perimeter-01` | Perímetro y detección | HAProxy, Coraza SPOA, Suricata, Vector edge, firewall-bouncer |
| `pipeline-01` | Bus | Kafka, Vector aggregator |
| `intel-01` | Inteligencia | CrowdSec LAPI, Vector intel |
| `store-01` | Datos | ClickHouse, node_exporter |
| `obs-01` | Observabilidad | Prometheus, Grafana, cAdvisor, node_exporter |

Cada nodo expone sus métricas por `node_exporter` y se registra en el catálogo
de Consul con la etiqueta correspondiente, de modo que Prometheus los descubre
sin configuración estática de IPs.

---

## 7. Operación

Los procedimientos de mantenimiento (rotación de credenciales, caída de Kafka,
retención, purga de topics, recuperación del bouncer) están en
[`runbook.md`](runbook.md).
