# Catálogo de detecciones

Las **43 reglas activas** del entorno, repartidas en **37 ficheros de
escenario**, de las cuales **9 son propias** (no provienen del hub de
CrowdSec).

> [!NOTE]
> El inventario completo con los filtros exactos de cada regla está en los
> ficheros de `config/crowdsec/scenarios/`. Este documento describe **qué
> detecta cada familia** y **por qué está en el entorno**.

---

## 1. Las dos clases de regla

CrowdSec distingue dos tipos de escenario, y la diferencia explica casi todo
el comportamiento del sistema:

| Tipo | Se dispara | Uso |
|---|---|---|
| `trigger` | Al primer evento que cumple el filtro | Detección inequívoca: una exploit, un patrón de ataque conocido |
| `leaky` | Requiere **N eventos distintos** en una ventana de tiempo | Detección por patrón: requiere accumulating evidencia |

La regla `leaky` es la que discrimina un ataque de un cliente legítimo. Un
usuario que recibe un `404` no es un atacante; diez IPs distintas que reciben
un `404` en la misma ruta sí lo son.

Cada regla `leaky` tiene tres parámetros que gobiernan su comportamiento:

| Parámetro | Significado |
|---|---|
| `capacity` | Número de eventos distintos que hay que acumular |
| `leakspeed` | Ventana temporal en la que se acumulan |
| `blackhole` | Tiempo que se ignoran los eventos posteriores del mismo grupo |

---

## 2. Reglas propias del entorno (9 ficheros)

### 2.1 Severidad del IDS — `suricata-alerts.yaml`

| Regla | Tipo | Condición | Comportamiento |
|---|---|---|---|
| `crowdsecurity/suricata-major-severity` | `trigger` | Alerta del IDS de **severidad 1** (crítica) | Ban inmediato, `blackhole` 1 min |
| `crowdsecurity/suricata-high-medium-severity` | `leaky` | Severidad 2, **2 firmas distintas** en 20 s | Ban si se repite |

**Por qué dos reglas y no una.** La severidad 1 del IDS es una firma de
explotación: se ban al primer evento. La severidad 2 es más ambigua (puede ser
un escáner legítimo o un ataque automatizado), así que exige que aparezcan
**dos firmas diferentes** en la misma ventana. Banear a la primera señal de
severidad 2 generaría falsos positivos en servidores que responden `404` a
rutas inexistentes.

**Decisión consciente:** no hay regla para la severidad 3. El volumen de
severidad 3 es enorme y su valor de detección marginal.

### 2.2 Backdoors — `http-backdoors-attempts.yaml`

Regla `leaky`, capacidad 1, `leakspeed` 5 s, `blackhole` 5 min. Detecta
peticiones a rutas de backdoor conocidas (lista `sec-lists` de CrowdSec).
Etiqueta: `discovery` + `remediation`.

### 2.3 Ficheros sensibles — `http-sensitive-files.yaml`

Regla `leaky`, capacidad 4, `leakspeed` 5 s, `blackhole` 5 min. Detecta el
acceso a ficheros de configuración, bases de datos o directorios de control de
versiones (`.git`). Cuatro accesos distintos son un escaneo; uno solo puede
ser una curiosidad.

### 2.4 Rastreo agresivo — `http-crawl-non_statics.yaml`

Regla `leaky`, capacidad 40, `leakspeed` 0,5 s, `blackhole` 1 min.
Distinguido por `ip + fqdn`, de modo que el mismo cliente puede rastrear
varios sitios sin que se sumen entre sí.

### 2.5 Sondeo web — `http-probing.yaml`

Regla `leaky`, capacidad 10, `leakspeed` 10 s, `blackhole` 5 min. Detecta
peticiones con `404`/`403`/`400` sobre recursos no estáticos. Es la regla que
más bans produce: **759 decisiones sobre 225 IPs**.

### 2.6 Others propios

Ficheros de exploit por CVE (con exploits público de tipo RCE, LFI, bypass de
autenticación), un detector de *modsecurity* y reglas de enumeración de
usuarios por credenciales por defecto.

---

## 3. Reglas heredadas del hub

### 3.1 Detección genérica de fuerza bruta

| Regla | Objetivo |
|---|---|
| `crowdsecurity/http-generic-bf` | Fuerza bruta HTTP |
| `crowdsecurity/ssh-bf` | Fuerza bruta SSH |
| `crowdsecurity/ssh-slow-bf` | Fuerza bruta SSH de baja cadencia |

Las tres son `leaky` con `leakspeed` largo, porque la diferencia entre un
atacante y un usuario que falla la contraseña tres veces es **la
persistencia**.

### 3.2 Patrones de ataque en la capa web

| Regla | Objetivo |
|---|---|
| `crowdsecurity/http-sqli-probing` | Patrones de inyección SQL |
| `crowdsecurity/http-xss-probing` | Patrones de XSS |
| `crowdsecurity/http-path-traversal-probing` | Recorrido de rutas |
| `crowdsecurity/http-open-proxy` | Uso abusivo de open proxy |
| `crowdsecurity/http-bad-user-agent` | User agents de herramienta de ataque |
| `crowdsecurity/http-w00tw00t` | Patrones de utillaje ofensivo |

### 3.3 Exploits por CVE

Un escenario por CVE con exploit público conocido: WordPress, Drupal, GitLab,
Jira, Spring4Shell, ThinkPHP, Fortinet, VMware, F5, Log4Shell (incluida la
variante de *lookup* vía cabecera o referer) y otras.

Todos usan `remediation: true`, que es lo que permite al bouncer actuar.

### 3.4 Reglas de infraestructura

| Regla | Objetivo |
|---|---|
| `crowdsecurity/nginx-req-limit-exceeded` | Límite de peticiones excedido |
| `crowdsecurity/modsecurity` | Evento genérico del WAF |

---

## 4. Reglas heredadas del hub

| Regla | Tipo | Capacidad / ventana | blackhole | Etiqueta |
|---|---|---|---|---|
| `http-probing` | leaky | 10 / 10 s | 5 m | scan |
| `http-crawl-non_statics` | leaky | 40 / 0,5 s | 1 m | crawl |
| `http-backdoors-attempts` | leaky | 1 / 5 s | 5 m | discovery |
| `http-sensitive-files` | leaky | 4 / 5 s | 5 m | discovery |
| `http-generic-bf` | leaky | 10 / 5 s | 5 m | bruteforce |
| `http-sqli-probing` | leaky | 10 / 10 s | 5 m | exploit |
| `http-xss-probing` | leaky | 10 / 10 s | 5 m | exploit |
| `http-path-traversal-probing` | leaky | 10 / 10 s | 5 m | exploit |
| `http-open-proxy` | leaky | 10 / 10 s | 5 m | exploit |
| `http-bad-user-agent` | leaky | 1 / 5 s | 5 m | exploit |
| `http-w00tw00t` | leaky | 10 / 10 s | 5 m | exploit |
| `ssh-bf` | leaky | 5 / 10 s | 5 m | bruteforce |
| `ssh-slow-bf` | leaky | 20 / 60 s | 5 m | bruteforce |
| `nginx-req-limit-exceeded` | leaky | 10 / 10 s | 5 m | flood |
| `modsecurity` | leaky | 5 / 10 s | 5 m | exploit |
| `suricata-major-severity` | trigger | — / — | 1 m | exploit |
| `suricata-high-medium-severity` | leaky | 2 / 20 s | 1 m | exploit |
| `http-cve-2021-41773` | leaky | 10 / 10 s | 5 m | exploit |
| `http-cve-2021-42013` | leaky | 10 / 10 s | 5 m | exploit |
| `jira_cve-2021-26086` | leaky | 10 / 10 s | 5 m | exploit |
| `apache_log4j2_cve-2021-44228` | trigger | — / — | 5 m | exploit |
| `spring4shell_cve-2022-22965` | trigger | — / — | 5 m | exploit |
| `thinkphp_cve-2018-20062` | trigger | — / — | 5 m | exploit |
| `CVE-2022-26134` | trigger | — / — | 1 m | exploit |
| `CVE-2022-35914` | trigger | — / — | 1 m | exploit |
| `CVE-2022-37042` | trigger | — / — | 2 m | exploit |
| `CVE-2022-40684` | trigger | — / — | 2 m | exploit |
| `CVE-2022-41082` | trigger | — / — | 1 m | exploit |
| `CVE-2022-41697` | leaky | 5 / 10 s | 1 m | exploit |
| `CVE-2022-42889` | trigger | — / — | 1 m | exploit |
| `CVE-2022-44877` | trigger | — / — | 1 m | exploit |
| `CVE-2022-46169` | leaky + trigger | 5 / 10 s | 1 m | exploit |
| `f5-big-ip-cve-2020-5902` | trigger | — / — | 5 m | exploit |
| `fortinet-cve-2018-13379` | trigger | — / — | 5 m | exploit |
| `grafana-cve-2021-43798` | trigger | — / — | 5 m | exploit |
| `pulse-secure-sslvpn-cve-2019-11510` | trigger | — / — | 5 m | exploit |
| `vmware-cve-2022-22954` | trigger | — / — | 5 m | exploit |
| `vmware-vcenter-vmsa-2021-0027` | trigger | — / — | 5 m | exploit |

---

## 5. Adquisición

CrowdSec no lee de Kafka directamente: consume **ficheros de log**. El
agente Vector del nodo de inteligencia escribe en
`/var/log/crowdsec-pipeline/<servicio>.log` y CrowdSec los adquiere desde ahí.

| Fichero de adquisición | Tipo declarado | Origen |
|---|---|---|
| `acquis.d/haproxy.yaml` | `haproxy-custom` | Topic `security-logs-haproxy` |
| `acquis.d/suricata.yaml` | `suricata-evelogs` | Topic `security-logs-suricata` |
| `acquis.d/coraza.yaml` | `coraza` | Topic `security-logs-coraza` |
| `acquis.d/apache.yaml` | `apache2` | Topic `security-logs-apache` |

Ver [`config/crowdsec/acquis.d/`](../config/crowdsec/acquis.d/).

---

## 6. Métricas

CrowdSec expone Prometheus en `:6060`:

| Métrica | Qué mide |
|---|---|
| `cs_alerts` | Alertas generadas |
| `cs_active_decisions` | Decisiones activas ahora |
| `cs_node_hits_ok_total` / `cs_node_hits_ko_total` | Líneas leídas y parseadas con éxito / error |
| `cs_parser_hits_ok_total` / `cs_parser_hits_ko_total` | Cobertura de los parsers |
| `cs_bucket_overflowed_total` | Buckets que desbordaron su capacidad |
| `cs_lapi_request_duration_seconds` | Latencia de la API |
| `cs_filesource_hits_total` | Eventos leídos por fuente de fichero |

**`cs_node_hits_ko_total` es la métrica que hay que vigilar**: si sube, el
formato de log de origen ha cambiado y el parser ya no entiende el mensaje.
Es la señal de que un `remap` de Vector necesita actualizarse.
