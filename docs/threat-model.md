# Modelo de amenazas

Qué se protege, de quién, con qué superficie y qué mitigación hay en cada
caso. El alcance es el entorno de laboratorio perimetral y su pipeline de
datos; no cubre los backends de aplicación, que tienen su propio modelo.

---

## 1. Activos

| # | Activo | Por qué importa | Impacto si se compromete |
|---|---|---|---|
| A1 | **Tráfico de negocio** | Es el activo que produce el valor del perímetro | Exposición de datos, suplantación de sesión |
| A2 | **Credenciales del WAF** | La llave que permite a una fuente externa atravesar las detecciones | Inyección de datos arbitrarios en el almacén analítico, evitación del WAF |
| A3 | **Credenciales de ingesta** | Permiten escribir en el almacén de telemetría | Envenenamiento del histórico: falsear decisiones, alertas y auditorías |
| A4 | **Decisiones de bloqueo** | Definen quién está bloqueado | Evasión del bloqueo; en el peor caso, bloqueo de terceros |
| A5 | **Histórico de telemetría** | Es la evidencia para investigación y auditoría | Pérdida de trazabilidad; confianza ciega en datos manipulados |
| A6 | **Disponibilidad de la ingesta** | Si el pipeline para, no hay detección | Ceguera operacional |
| A7 | **Métricas** | Alimentan alertas y capacidad | Decisiones sobre datos equivocados |

---

## 2. Actores

| Actor | Capacidad | Objetivo |
|---|---|---|
| **Escáner oportunista** | Automatizado, masivo, sin persistencia | Reconocimiento y difusión amplia de vulnerabilidades conocidas |
| **Atacante automatizado** | Herramientas (scanners, fuzzers), capacidad de reintento | Explotar y escalar |
| **Atacante manual** | Interactivo, paciente | Objetivo específico y dwell time largo |
| **Bot de recompensa / researcher** | Legal pero ruidoso | Reportar hallazgos; legítimamente escanea |
| **Actor interno** | Acceso a un nodo o a un fichero de configuración | Acceso lateral, exfiltración |
| **Insumo de terceros** | Proporciona una librería o un servicio que se integra | Introducir una vulnerabilidad o una puerta trasera en la cadena |

---

## 3. Superficie de ataque

| Superficie | Vector | Controles |
|---|---|---|
| **HTTP/HTTPS público** | Inyección SQL, XSS, LFI, traversal, subida de ficheros, SSRF | WAF con CRS, revisión de falsos positivos por excepción acotada |
| **TLS** | Versiones obsoletas, cipher débiles, interceptación | Terminación única en el proxy, HSTS, redirect forzado |
| **Cabeceras de cliente** | `CF-Connecting-IP` falsificado | Validación del rango de origen del CDN antes de aceptar la cabecera |
| **Ficheros de log** | Inyección de líneas de log para falsificar eventos | Normalización y parseo en el edge; el `raw_json` conserva el original para auditoría |
| **Bus de eventos** | Inyección de mensajes en un topic | Autenticación del broker; topics separados por servicio |
| **Almacén analítico** | Escritura arbitraria desde la credencial de ingesta | Usuario con `INSERT` únicamente, sin `SELECT` ni `ALTER` |
| **API del LAPI** | Uso indebido de la API key del bouncer | Key por bouncer, revocable y rotable de forma independiente |
| **Configuración del WAF** | Reglas desactivadas para no perder tráfico | Excepciones **por token y por objetivo**, nunca por regla completa |
| **Host perimetral** | Escalada local desde un servicio comprometido | Auditoría de kernel (pendiente, ver [ADR-007](adr/007-runtime-ebpf.md)) |
| **Capa de datos** | Manipulación de la telemetría operativa | Reglas de calidad en la normalización; criterio de prevalencia sin promediar |

---

## 4. Escenarios y mitigaciones

### T1 · Inyección de logs para envenenar el histórico

**Técnica.** Un atacante que consiga escribir en un fichero de log (o en un
topic) inserta líneas con formato de log válido, imitando a un evento
legítimo. El histórico muestra una actividad que no ocurrió.

**Impacto.** Se falsea la evidencia de auditoría, se pueden ocultar ataques
reales y se pueden disparar o silenciar alertas.

**Mitigaciones.**

- La credencial de ingesta tiene **`INSERT` y nada más**: no puede leer ni
  borrar lo que ya está escrito.
- El `raw_json` conserva el evento original **antes** de la normalización, de
  modo que una manipulación en la capa de parseo es detectable comparando
  ambos.
- La normalización se hace en el edge, con esquemas cerrados y campos
  tipados: un campo que no encaja no se escribe.
- El histórico tiene **TTL de 3 meses**: la ventana de manipulación es
  acotada.

**Riesgo residual.** Un atacante con acceso de escritura al host perimetral
puede escribir directamente en el topic. El control efectivo es el acceso al
host, no el bus.

### T2 · Bypass del WAF con la credencial de excepción

**Técnica.** La credencial de excepción permite que una fuente externa
atraviese las detecciones. Si se filtra, cualquiera puede hacer peticiones que
el CRS no inspecciona.

**Impacto.** Bypass completo del WAF; inyección de datos en el almacén
analítico a través del perímetro.

**Mitigaciones.**

- El valor es un **secreto de alta entropía**, generado, no derivado.
- La excepción es **acotada por objetivo**: se retiran detecciones
  *argumento* de familias concretas (SQLi, PHP, RCE, XSS, LFI, RFI), nunca
  reglas enteras. El resto del CRS sigue aplicándose.
- La regla que lo implementa está **en fase 2** (post-cuerpo), de modo que
  la petición tiene que superar el resto del procesamiento.
- La credencial **se rota** sin necesidad de tocar reglas: es un valor en una
  directiva.

**Riesgo residual.** La credencial es un factor único: no hay segundo factor
ni restriction por origen. Es la desviación más grande del diseño y la
primera candidata a endurecer (restringir por IP de origen conocida).

### T3 · Abuso de la API key del bouncer

**Técnica.** Con la key, se pueden registrar bouncers adicionales contra el
LAPI, consultar el histórico de decisiones o inyectar decisiones.

**Impacto.** Filtración de la política de bloqueo y de la lista de IPs
atacantes; posibilidad de bloquear IPs de terceros.

**Mitigaciones.**

- Una key por bouncer: se revoca una sin tocar las demás.
- El LAPI restringe las IPs de administración por `trusted_ips`.
- Las decisiones se pueden auditar contra el histórico de ClickHouse.

**Riesgo residual.** El bouncer de firewall necesita el privilegio de
manipular el filtrado de paquetes en el host perimetral. Es,
inevitablemente, una credencial privilegiada en la máquina más expuesta.

### T4 · Disparo masivo de falsos positivos

**Técnica.** Un cliente legítimo genera peticiones que el CRS marca como
ataque, o un atacante genera volumen para provocar el bloqueo de un tercero
(*ban baiting*).

**Impacto.** Bloqueo de clientes legítimos; pérdida de confianza en el
sistema de bloqueo.

**Mitigaciones.**

- Las reglas `leaky` exigen **N eventos distintos** en ventana.
- El `blackhole` evita el reprocesamiento constante del mismo atacante.
- La blacklist del WAF es una **excepción acotada y documentada**, no una
  exclusión masiva.
- Las IP internas y los rangos del CDN se tratan de forma explícita.

### T5 · Exfiltración por el canal de telemetría

**Técnica.** Usar el canal de logs como canal de salida: escribir datos
sensibles en un campo de log que acaba en un almacén accesible.

**Impacto.** Filtración de datos vía un canal que suele considerarse de
confianza interna.

**Mitigaciones.**

- El campo `message` / `raw_json` contiene el evento original: es una
  auditoría, no un canal de salida controlado.
- La credencial de ingesta no puede **leer**: quien escribe no puede leer lo
  que otros escribieron.
- El acceso de lectura es un usuario distinto y de solo lectura.

**Riesgo residual.** El `raw_json` conserva el evento íntegro por diseño
(auditoría forense). Es una superficie de retención que hay que conocer: el
TTL de 3 meses es también la ventana de exposición.

### T6 · Agotamiento de recursos del pipeline

**Técnica.** Provocar picos de volumen de eventos (por ejemplo, provocando
alarmas del IDS) hasta degradar la ingesta o el almacén.

**Impacto.** Retraso en la detección, caída del pipeline, pérdida de eventos.

**Mitigaciones.**

- **Filtrado en el origen**: el 79,5 % del ruido histórico provenía de tres
  reglas de estado de TCP ([ADR-003](adr/003-filtrado-en-el-edge.md)).
- Retención por topic en Kafka, independiente del almacén analítico.
- Batching en la escritura (5.000 eventos) para no amplificar el coste por
  evento.
- TTL en el almacén: el pico de volumen no se convierte en presión
  permanente.

### T7 · Manipulación de la telemetría operativa

**Técnica.** Corruptir o duplicar registros de origen para alterar los
indicadores calculados.

**Impacto.** Decisiones operativas sobre datos falsos: umbrales de
cumplimiento, planificación de capacidad, decisiones de operación.

**Mitigaciones.**

- Deduplicación por clave compuesta.
- Criterio de prevalencia **sin promediar**: cuando dos fuentes discrepan se
  conservan ambas y se marca la prevalente, de modo que la discrepancia es
  visible en lugar de diluirse.
- Descarte de ceros no analíticos, valores fuera de rango físico y filas
  futuras.
- El agente autónomo **no escribe**: propone. La ejecución la decide una
  persona.

### T8 · Credenciales del cliente en la telemetría de seguridad

**Técnica.** El log de auditoría del WAF registra las cabeceras de la
petición, que incluyen las de autenticación del cliente. Ese log alimenta
la tabla de eventos de seguridad, de modo que la credencial queda escrita
en el propio histórico de auditoría.

**Impacto.** Una credencial con permisos amplios queda legible desde un
lugar que se supone de solo lectura, y desde ahí se salta al resto.

**Mitigaciones.**

- El WAF **no registra las cabeceras** de la petición (ADR-008). Si no se
  escribe, no hay que purgarlo después.
- La credencial del cliente de ingesta es de **escritura acotada** sobre las
  tablas destino, no la del usuario administrador.
- El endpoint público del almacén exige el **token de excepción**: un filtro
  de patrones SQL no es control de acceso, porque la misma consulta
  redactada de otra forma pasa.
- La retención acotada (3 meses) limita la ventana de exposición de lo que
  ya esté escrito.

**Riesgo residual.** El cuerpo de la petición sí se registra, y contiene
datos de negocio. Es una decisión consciente: es lo que da valor forense al
histórico, y el acceso a él está controlado por usuario.

---

## 5. Matriz de riesgo

| # | Escenario | Probabilidad | Impacto | Riesgo | Control principal |
|---|---|:--:|:--:|:--:|---|
| T1 | Inyección de logs | Media | Medio | 🟠 | Credencial `INSERT`-only + `raw_json` + TTL |
| T2 | Bypass del WAF con la credencial | Baja | Alto | 🔴 | Excepción acotada + secreto rotable + restricción por origen *(pendiente)* |
| T3 | Abuso de la API key del bouncer | Baja | Medio | 🟠 | Key por bouncer + `trusted_ips` + auditoría |
| T4 | Falsos positivos / ban baiting | **Alta** | Medio | 🟠 | Reglas `leaky` + `blackhole` + excepciones acotadas |
| T5 | Exfiltración por el canal de logs | Baja | Medio | 🟡 | Ingesta sin lectura + TTL de 3 meses |
| T6 | Agotamiento del pipeline | **Alta** | Medio | 🟠 | Filtrado en origen + retención por topic + TTL |
| T7 | Manipulación de la telemetría | Media | Medio | 🟡 | Reglas de calidad + prevalencia sin promediar + agentes sin escritura |
| T8 | Credenciales del cliente en la telemetría | **Alta** | Alto | 🔴 | WAF sin cabeceras (ADR-008) + credencial acotada + endpoint con token |

🔴 Alto · 🟠 Medio · 🟡 Bajo

---

## 6. Pendientes

| # | Acción | Prioridad |
|---|---|:--:|
| 1 | Restringir la excepción del WAF por IP de origen además de por token | Alta |
| 2 | Desplegar la detección en runtime (eBPF) para cubrir el host perimetral | Alta |
| 3 | Migrar el panel SOC a la capa semántica (`v_*`) | Media |
| 4 | Correlationar la reincidencia con la duración real del ban | Media |
| 5 | Alertas sobre `cs_node_hits_ko_total` (cambio de formato de log) | Media |
| 6 | Reglas de calidad del dato como código versionado, con tests | Baja |
| 7 | Copia de seguridad verificada del almacén analítico | Media |
| 8 | Cliente de ingesta con usuario de escritura acotada, no el administrador | Alta |
