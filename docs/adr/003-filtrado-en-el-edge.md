# ADR-003 · Filtrar el ruido en el origen, no en el destino

- **Estado:** aceptada
- **Fecha:** 2026-11
- **Ámbito:** pipeline de ingesta de telemetría de seguridad

## Contexto

El histórico de 90 días creció hasta **9.101.705 filas** (6,7 GB comprimidos,
50,4 GB sin comprimir). El crecimiento no era uniforme: había días con
**1,79 millones de filas** frente a una media de 5.000–50.000.

El análisis de composición mostró que el **79,5 %** del histórico provenía de
**tres reglas** del IDS:

```text
SURICATA STREAM Packet with invalid ack
SURICATA STREAM ESTABLISHED invalid ack
SURICATA STREAM ESTABLISHED packet out of window
```

Estas reglas describen anomalías del **estado TCP** (retransmisiones,
segmentación fuera de ventana, renegociación), no la intención de un
atacante. Son ruido puro: describen el transporte, no la amenaza.

## Decisión

Filtrar en **dos capas**, porque el ruido se paga en un sitio distinto en
cada una.

**Capa 1 · En el origen (Suricata).** Es la capa que de verdad importa: el
fichero de log se escribe *antes* de que el pipeline lo lea, así que filtrar
después no ahorra ni un byte de disco.

```apache
# /etc/suricata/threshold.config
# Reglas del motor STREAM (gid 1, severidad 3): describen anomalias de
# estado TCP (ack invalido, segmentacion fuera de ventana), no la
# intencion de un atacante.
suppress gen_id 1, sig_id 2210029   # ESTABLISHED invalid ack
suppress gen_id 1, sig_id 2210045   # Packet with invalid ack
suppress gen_id 1, sig_id 2210020   # ESTABLISHED packet out of window
```

**Capa 2 · En el edge (Vector).** Segunda red, por si el conjunto de reglas
del IDS cambia y aparece una regla ruidosa nueva:

```toml
[transforms.filter_suricata]
type = "filter"
inputs = ["format_suricata"]
condition = '''
.service == "suricata" && .event_type == "alert" && (.rule_severity <= 2) ?? true
'''
```

El `?? true` es importante: si el campo de severidad no está, el evento **se
conserva** en lugar de abortarse. En VRL, comparar un valor nulo es un error
en tiempo de ejecución, y un filtro que aborta descarta eventos que no sabe
clasificar. Mejor pasarlos.

El nivel de transporte (severidad 3) **se conserva en el topic de Kafka**, que
es donde se consulta para diagnóstico fino. Se pierde en el histórico
analítico, que es donde no aporta.

### Por qué el filtro tiene que ir en el origen

El histórico de telemetría del almacén no era el único problema: **el disco
del host perimetral se llenaba**. Con el ruido sin filtrar, el fichero de
eventos del IDS llegaba a **3,7 GB en un día** sobre un disco de 11 GB, con
14 rotaciones retenidas: el perímetro se quedó **al 100 %** y el agente de
registro dejó poder escribir sus *checkpoints*, con lo que la ingesta entera
se detuvo sin que nada fallara de forma visible.

Filtrar en el consumidor no habría arreglado nada de eso: los gigabytes ya
estaban escritos en el disco antes de que nadie los leyera.

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| Filtrar con `PARTITION BY` o tablas separadas | Complica las consultas y no reduce el espacio: el dato sigue ocupando disco |
| `TTL` más corto | Reduce el volumen a futuro, no el ya ingerido. Además, 90 días de retención es un requisito, no un descuido |
| Filtro en la consulta de Grafana | El dato sigue ocupando disco y red; sólo esconde el síntoma |
| `SAMPLE` / `LIMIT` en el insert | Rompe la completitud del histórico y hace la auditoría imposible |

## Consecuencias

**A favor:**

- El histórico baja de 9,1 M a **~1,9 M de filas** (-79,5 %) **sin perder
  ninguna detección real**.
- Los picos diarios de 1,7-1,8 M desaparecen: el problema no era el
  crecimiento, era la composición.
- Menos disco, menos I/O de escritura, menos presión de compactación.
- Las consultas analíticas sobre el histórico dejan de competir con el
  ruido.

**En contra:**

- El diagnóstico fino de anomalías TCP requiere consultar Kafka, no
  ClickHouse. El histórico deja de ser un superset del topic.
- Una lista de reglas que hay que mantener: si el conjunto de reglas del IDS
  cambia, la lista hay que revisarla.
- Riesgo de sobre-filtrado: si una regla descartada llegara a ser relevante
  para una detección, el evento ya no está en el histórico.

**Mitigación del riesgo de sobre-filtrado:** la lista es **explícita y
revisable**, no un comodín por severidad. Añadir una regla a la lista exige
justificarla en el pull request. Y el topic conserva todo, así que una
investigación puede reconstruirse desde el bus mientras la retención del
topic lo cubra.

**Efecto secundario sobre el disco.** Sin el filtro en origen, el host
perimetral se queda sin espacio y la ingesta se detiene sin error visible.
Es el motivo por el que el filtrado va acompañado de una política de
rotación de logs con `maxsize`, que fuerza la rotación aunque el día no se
haya llenado.

## Referencia

Detalle completo del análisis y del esquema v2 en
[`docs/arquitectura.md`](../arquitectura.md#4-optimización-el-795-de-ruido).
