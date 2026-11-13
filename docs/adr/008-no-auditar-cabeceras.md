# ADR-008 · No auditar cabeceras de petición en el WAF

- **Estado:** aceptada
- **Fecha:** 2026-11
- **Ámbito:** perímetro y telemetría de seguridad

## Contexto

El WAF audita las transacciones que disparan una regla. Por defecto, el log
de auditoría incluye **todas las cabeceras de la petición** (`SecAuditLogParts`
con la parte `B`).

Eso incluye las cabeceras de autenticación del cliente:

```http
X-ClickHouse-Key: <contraseña del almacén analítico>
X-Ingest-Token: <secreto de excepción del WAF>
```

Y el log de auditoría no es un archivo aislado: es **la fuente de la que se
alimenta la telemetría de seguridad**. El agente Vector del perimeter lo lee y
lo escribe, evento a evento, en la tabla de eventos de seguridad.

El resultado: **la contraseña del almacén analítico quedaba escrita en
claro dentro de la propia telemetría de seguridad**, en cada petición que el
WAF bloqueaba. Medido sobre un periodo de 90 días: 4.273 eventos afectados,
con la credencial completa en el campo de mensaje y en la copia original.

Y no era un documento muerto: la tabla se lee desde el panel de SOC, con un
usuario de solo lectura. Bastaba una consulta para extraer una credencial con
permisos sobre todas las bases.

El detalle que lo hacía peor: la contraseña del cliente es la del usuario
`default`, y el endpoint del almacén analítico **es público** (a través del
perímetro). El WAF bloqueaba las consultas con patrón SQL, pero eso es un
filtro de patrones, no control de acceso: la misma consulta redactada de otra
forma —`SELECT * FROM ... LIMIT 1` en lugar de `SELECT count() FROM ...`— se
ejecutaba sin objeción.

## Decisión

**El log de auditoría del WAF no registra las cabeceras de la petición.**

```apache
# Sin la parte B (cabeceras de la peticion).
SecAuditLogParts ACDEFGHZ
```

Además, la regla de excepción que desactiva las detecciones del CRS para la
fuente de datos autorizada pasa a ser un **valor de entorno**, no un literal
en el fichero.

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| **Redactar la cabecera en el agente Vector**, al escribir en el almacén | La copia original del evento (`raw_json`) se conserva para auditoría forense: la credencial seguiría dentro del propio registro |
| **Filtrar por IP de origen en el almacén** | El problema no es quién escribe, es qué se escribe. Un dato que no se guarda no se puede filtrar después |
| **No enviar credenciales por la cabecera `X-ClickHouse-Key`** | ClickHouse por HTTP exige autenticación por cabecera. La alternativa (un proxy que inyecte las credenciales del lado servidor) es la solución de raíz, pero añade un componente |
| **Dejar la auditoría como estaba y confiar en la rotación** | La rotación invalida la credencial, pero deja 4.273 filas con la credencial antigua, más el log en disco. Hay que purgar igualmente |

## Consecuencias

**A favor:**

- **La credencial no llega a existir donde se lee.** Si no se registra, no se
  filtra y no hay que purgar.
- Reduce el volumen del histórico de telemetría de forma notable: las
  cabeceras eran la mayor parte del tamaño de un evento de auditoría.
- El coste forense es bajo: las cabeceras de la petición se pueden recuperar
  del log del proxy, cuyo formato es propio y **no incluye cabeceras**.

**En contra:**

- **Se pierde información forense.** La auditoría del WAF deja de mostrar
  cabeceras: no se puede ver, por ejemplo, el `User-Agent` ni qué cabeceras
  añadieron. Para una investigación, el log del proxy y el histórico de
  eventos siguen dando la traza.
- El cuerpo de la petición (`C`) **sigue** registrándose. Contiene los datos
  de negocio, que es justo lo que interesa en una auditoría.
- Un atacante que llegue a leer el log de auditoría ya no ve las cabeceras:
  pierde información sobre qué intentaba.

**Consecuencia operativa:** el histórico de telemetría contiene datos de
negocio (el cuerpo de las peticiones). Eso no es nuevo, pero conviene
recordarlo al definir la retención y los accesos.

## Referencia

- Configuración: [`config/coraza/coraza.conf`](../config/coraza/coraza.conf)
- Procedimiento de respuesta ante una credencial filtrada:
  [`docs/runbook.md`](../runbook.md#3-5-credencial-filtrada-en-la-telemetria)
- Escenario del modelo de amenazas:
  [`docs/threat-model.md`](../threat-model.md)
