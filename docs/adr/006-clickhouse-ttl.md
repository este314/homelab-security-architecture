# ADR-006 · ClickHouse con TTL y diccionario GeoIP

- **Estado:** aceptada
- **Fecha:** 2026-08
- **Ámbito:** almacenamiento analítico de la telemetría de seguridad

## Contexto

El histórico de seguridad tiene dos características que condicionan el
almacenamiento:

1. **Volumen alto y creciente**: ~9,1 M de filas en 90 días, con picos
   diarios de 1,8 M (ver [ADR-003](003-filtrado-en-el-edge.md)).
2. **Valor decreciente con el tiempo**: una alerta de hace seis meses es un
   dato histórico; una de hace seis días puede ser la base de una
   investigación.

Además, la analítica de seguridad necesita **enriquecer por país y ASN**, lo
que implica un join contra una tabla de rangos que no cambia.

## Decisión

**ClickHouse con `TTL` para acotar el histórico y un diccionario `IP_TRIE`
para el enriquecimiento geográfico.**

```sql
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (service, src_ip, timestamp)
TTL toDateTime(timestamp) + INTERVAL 3 MONTH
```

El diccionario:

```sql
CREATE DICTIONARY security.geoip_dict
(
    cidr         String,
    country_code String,
    country_name String
)
PRIMARY KEY cidr
SOURCE(CLICKHOUSE(DB 'security' TABLE 'geoip_ranges'))
LAYOUT(IP_TRIE())
```

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| PostgreSQL | Row-store: el escaneo analítico sobre 9 M de filas con agregaciones por minuto y por IP es exactamente el caso donde un row-store sufre |
| TimescaleDB | El problema de espacio y de retención por extensión es menor que el de motor de columnas, pero el modelo de "hipertabla" no aporta sobre `MergeTree` |
| Loki | Excelente para consultar logs por etiquetas; no es un almacén analítico. Cálculos como "top IPs por minuto con ventana móvil" se resuelven en el cliente, no en el motor |
| Elasticsearch | Búsqueda de texto completo superbena; el coste en RAM y en disco para 9 M de filas es alto y no aporta consultas de agregación |
| Sin TTL, purga manual | El histórico crece sin límite y la operación de purgar es manual y propensa a errores |
| Join con `LEFT JOIN` en vez de diccionario | El join se recalcula en cada consulta sobre 3,7 M de rangos: el diccionario resuelve la búsqueda en el índice `IP_TRIE`, con coste de memoria amortizado |

## Consecuencias

**A favor:**

- **El espacio está acotado por diseño**: la retención es una propiedad del
  motor, no una tarea.
- **Ratio de compresión alto**: 50,4 GB sin comprimir → 6,7 GB en disco
  (7,5×), con `Delta` para las columnas temporales y `LowCardinality` para las
  de texto repetitivo (servicio, nivel, método HTTP, país).
- **Consultas analíticas baratas**: las agregaciones por minuto y por IP son
  la operación natural de un column store.
- **El enriquecimiento por país no cuesta una consulta**: el diccionario se
  resuelve en memoria.
- **Particionado mensual**: permite descartar un mes entero con un `DROP
  PARTITION` en vez de un `DELETE` masivo.

**En contra:**

- **No es un almacén transaccional.** No hay Atomicidad, no hay
  multicolumna. Es correcto para su propósito, pero no sirve para estado.
- **El `TTL` se aplica en background merges.** Las piezas expiradas siguen en
  disco hasta que se fusionan. Con la configuración por defecto, el retraso
  es de horas, no de días, pero un `TTL` no es una promesa de borrado
  instantáneo.
- **El diccionario en memoria**: 3,7 M de rangos ocupan RAM de forma
  permanente. Es aceptable en este tamaño; en un orden de magnitud más,
  obligaría a replantear el enriquecimiento.
- **Un solo broker**: no hay replicación. La pérdida del nodo es la pérdida
  del histórico. Aceptable para telemetría de seguridad (los eventos crudos
  siguen en el bus mientras dure su retención), no para nada más.

**Mitigaciones:**

- Copia de seguridad periódica de la base (el `runbook.md` documenta el
  procedimiento y la verificación de restauración).
- El histórico se puede reconstruir desde Kafka mientras la retención del
  topic lo cubra.
- Para la escala en la que el coste de una pérdida de nodo deje de ser
  aceptable, la vía es un broker con replicación, no un cambio de motor.

## Referencia

Esquema: [`config/clickhouse/schema.sql`](../../config/clickhouse/schema.sql).
Capa semántica: [`config/clickhouse/views.sql`](../../config/clickhouse/views.sql).
