# ADR-001 · Kafka como buffer entre el borde y el destino

- **Estado:** aceptada
- **Fecha:** 2026-08
- **Ámbito:** pipeline de ingesta de telemetría de seguridad

## Contexto

El perímetro produce eventos de cuatro fuentes distintas (proxy, IDS, WAF,
aplicación) a un ritmo variable. El destino natural de esos eventos es
ClickHouse, que es también el destino de las métricas de CrowdSec y de los
registros de decisión.

La primera versión del pipeline escribía **directamente** desde el agente de
borde a ClickHouse. Funcionaba, pero tenía dos problemas que se hicieron
evidentes con el tráfico real:

1. **Acoplamiento**: si ClickHouse estaba reiniciándose o saturado, el
   perímetro perdía eventos, o el agente de borde bloqueaba el hilo de
   escritura y retrasaba la publicación de eventos de otras fuentes.
2. **Trabajo duplicado**: CrowdSec necesita el mismo flujo que el histórico.
   Con la escritura directa, había que leer el fichero de log por segunda vez
   desde otra máquina.

## Decisión

Insertar **Apache Kafka** entre el borde y el destino, con **un topic por
servicio de origen** (`security-logs-<servicio>`).

```text
Vector edge ─► Kafka (security-logs-*) ─┬─► Vector aggregator ─► ClickHouse
                                         └─► Vector intel ─► CrowdSec
```

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| Escritura directa borde → ClickHouse | Acoplamiento fuerte; sin replay; obligaba a releer ficheros en un segundo nodo |
| Solo ficheros, sin bus | La resiliencia de los ficheros no compensa: sin offsets, sin consumo concurrente, sin control de retención por topic |
| NATS / Redis Streams | Más simples, pero el ecosistema de clientes y la operativa de un broker Kafka ya eran conocidos; el coste de aprendizaje se paga una vez |
| Un único topic para todo | Obliga a cada consumidor a filtrar por servicio dentro del topic; el coste de CPU del filtro se paga en todos los consumidores |

## Consecuencias

**A favor:**

- El destino puede estar caído sin pérdida de eventos. El buffer absorbe
  reinicios y ventanas de mantenimiento.
- Replay: `auto_offset_reset = beginning` permite reprocesar el histórico
  desde el topic.
- Varios consumidores sobre el mismo bus sin duplicar la recolección.
- Retención por topic, independiente de la retención del almacén analítico.

**En contra:**

- Un componente más que operar y monitorizar.
- Un salto de red en el camino del log (≈ 1 ms intra-datacenter).
- El bus es **crítico**: si Kafka se cae, se detiene la ingesta hasta que
  vuelve. Es un punto único de fallo, aunque con retención en disco.

**Mitigación del punto único de fallo:** en operación mono-nodo, Kafka corre
con `KAFKA_LOG_DIRS` persistente y replicación a nivel de factor 1. El
`runbook.md` documenta el procedimiento de recuperación y el criterio para
migrar a multi-broker.

## Evidencia

El histórico de 90 días contiene **9.101.705 eventos** con una caída de
ClickHouse de varios minutos en el periodo, sin pérdida de eventos en el
tráfico del perímetro.
