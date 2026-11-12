# ADR-002 · CrowdSec central, sin agente de detección por nodo

- **Estado:** aceptada
- **Fecha:** 2026-08
- **Ámbito:** inteligencia de amenazas y bloqueo

## Contexto

El entorno tiene varios nodos con roles distintos (perímetro, bus,
inteligencia, datos, observabilidad) y ninguno es un servidor de aplicación
tradicional. La pregunta de diseño es dónde vive la lógica de detección.

El patrón habitual de un SIEM o de un IDS distribuido es **un agente por
nodo**: cada host envía sus logs a un colector que los indexa. En variantes
más NILWARE, el colector también corre reglas.

## Decisión

**Un único cerebro de detección** (CrowdSec LAPI) que procesa todos los logs,
y **bouncers stateless** que ejecutan las decisiones donde deben aplicarse.

```text
                    ┌──────────────────────────┐
  logs de todos  ─► │  CrowdSec LAPI (único)   │ ─► decisiones
  los nodos        │  parseo · buckets ·       │
                    │  escenarios · reputación  │
                    └──────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
            bouncer en el perímetro          bouncer (futuro) en otros nodos
```

El flujo de logs hacia el LAPI no requiere un agente por nodo: es el mismo
camino de Kafka que ya alimenta el histórico.

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| fail2ban por nodo | Cada nodo mantiene sus propias reglas y su propio estado; las IPs atacantes se re-banean N veces y el coste de CPU se replica N veces |
| Wazuh / OSSEC (HIDS) | Es un SIEM completo: indexa, correlaciona y almacena. Aquí el histórico ya lo hace ClickHouse; solapar.indexación duplicaría almacenamiento y CPU |
| Suricata con blocking inline | Suricata detecta, pero no tiene modelo de reputación ni de correlación temporal. La decisión de bloquear requiere ese modelo |
| Elastic / OpenSearch + SIEM | Motor de búsqueda de texto completo: útil para buscar log libre, caro para el escaneo analítico que hace ClickHouse sobre columnas |

## Consecuencias

**A favor:**

- **Coste cero en cada nodo.** Sólo el perímetro tiene un bouncer, y es
  ligero (un set de nftables).
- **Una sola fuente de verdad** sobre qué está bloqueado y por qué.
- **Reglas desplegables centralmente.** Añadir una regla nueva es un fichero
  en un nodo, no un despliegue en todos.
- Reconstruir un bouncer desde cero: menos de un minuto.
- El histórico de decisiones queda disponible para análisis (24,1 M de
  registros), lo que permite medir la eficacia del bloqueo.

**En contra:**

- **Punto único de fallo.** Si el LAPI cae, se siguen viendo eventos pero
  no se generan nuevas decisiones. El bouncer mantiene las decisiones ya
  aplicadas.
- **Coste de red.** Todos los logs van al nodo de inteligencia. En un entorno
  de un solo datacenter es irrelevante; en un despliegue distribuido,
  obligaría a mirroring.
- El LAPI es un estado que hay que respaldar: sin él se pierden las
  decisiones históricas (los eventos brutos siguen en ClickHouse).

**Mitigación del punto único de fallo:** el LAPI es **stateless respecto a la
aplicación** (el estado está en su base SQLite local) y puede reconstruirse
desde la configuración y los escenarios. La pérdida de estado solo afecta al
histórico de decisiones, no a la capacidad de volver a decidir.

## Evidencia

43 reglas activas (37 ficheros de escenario, 9 de ellos propios del
entorno). 24.100.100 decisiones registradas. Ban medio aplicado en **≤ 10 s**
desde el evento.
