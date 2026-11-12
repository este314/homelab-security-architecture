# ADR-007 · Seguridad en runtime con eBPF sobre el mismo bus de eventos

- **Estado:** **aceptada, pendiente de despliegue**
- **Fecha:** 2026-11
- **Ámbito:** detección en el host y en los contenedores

## Contexto

El perímetro ve las peticiones. El IDS ve el tráfico. Pero hay actividad que
ninguno de los dos observa:

- Un contenedor que abre una shell interactiva.
- Un proceso que escribe en `/etc/shadow` o en las claves SSH.
- Un binario desconocido ejecutado dentro de un contenedor de aplicación.
- Un proceso que hace `ptrace` sobre otro, o que monta un volumen sensible.

Esta actividad solo es visible desde dentro del kernel: **eBPF**.

El diseño de seguridad del entorno ya cubre bien el perímetro. Falta la
capa interna.

## Decisión

**Falco** para la detección en runtime (eBPF sobre las llamadas al sistema) y
**falcosidekick** como enrutador de eventos, publicando en el **mismo bus de
eventos** que ya usan el perímetro y el pipeline de datos.

```text
Falco (eBPF) ─► falcosidekick ─► Kafka: security-logs-falco ─┐
                                                              ├─► Vector aggregator ─► ClickHouse
Kafka: security-logs-haproxy ─────────────────────────────────┘
```

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| Wazuh (HIDS) | Es un SIEM completo con su propio indexado y su propio panel. Aquí el histórico ya lo cubre ClickHouse; solapar la indexación duplicaría almacenamiento y CPU |
| Auditd + una regla | Cobertura débil por defecto, reglas frágiles y salida en texto que hay que parsear. Falco da eventos estructurados y reglas de alto nivel |
| eBPF en casa | El coste de escribir, mantener y depurar programas eBPF propios es alto. Falco da un lenguaje de reglas y un catálogo de reglas ya mantenido |
| Falco → webhook directo a ClickHouse | Introduce un camino de ingesta nuevo, con su propio formato y su propia forma de fallar. Con falcosidekick, Falco speaks el idioma que el resto del bus ya entiende |
| Falco → Loki | Loki no es el almacén analítico de este entorno; obligaría a duplicar el histórico |

## Consecuencias

**A favor:**

- **Un solo camino de ingesta.** Falco no introduce un segundo formato ni un
  segundo destino: el aggregator que ya existe escribe en la misma tabla.
- **Cubre lo que el perímetro no puede ver.** Una shell abierta en un
  contenedor no genera ninguna petición HTTP.
- **El bucle se cierra**: el evento de runtime se correlaciona con la
  petición que lo originó, porque ambos comparten esquema y timestamp.
- **`falco-no-driver`** evita recompilar el kernel: usa eBPF en modo usuario
  con el driver moderno.
- falcosidekick permite añadir destinos (webhook, cola de mensajes) sin tocar
  la configuración de Falco.

**En contra:**

- **Falta el despliegue.** Es la parte del diseño que aún no está en
  producción.
- **Requiere privilegios**: Falco necesita `CAP_SYS_ADMIN` (o el driver de
  eBPF sin privilegios) y lectura de los eventos del kernel.
- **Coste de CPU en el nodo**: las reglas de Falco evaluan syscall por
  syscall. Un conjunto de reglas amplio en un host con muchos procesos
 进程的 puede notarse.
- **Volumen de eventos**: sin filtrado, un sistema con mucho ruido de
  syscalls genera un volumen alto. Habrá que aplicar el mismo criterio que
  en [ADR-003](003-filtrado-en-el-edge.md): filtrar en el origen.
- **No sustituye a un IDS de host**: Falco ve el comportamiento, no el
  paquete.

## Plan de despliegue

1. **Perfil de reglas mínimo.** Empezar con el conjunto por defecto de
   Falco, sin reglas propias, y medir volumen.
2. **Filtrado en el origen.** Descartar en falcosidekick los eventos de
   prioridad informativa que no aporten, con el mismo criterio de severidad
   que en el pipeline de seguridad.
3. **Esquema `security.falco_events`** y su vista en la capa semántica.
4. **Panel en el SOC**: eventos de runtime junto a los de red, con el mismo
   filtro por IP de origen, para poder ver "qué petición originó este
   evento de runtime".
5. **Reglas propias** específicas del entorno, derivadas de lo que se
  observe en los primeros días.

## Referencia

Configuración propuesta: [`config/falco/falco.yaml`](../../config/falco/falco.yaml).
