# ADR-004 · WAF integrado en el proxy vía SPOE

- **Estado:** aceptada
- **Fecha:** 2026-08
- **Ámbito:** perímetro

## Contexto

El perímetro necesita tres cosas que rara vez conviven bien: terminación TLS,
enrutado por nombre de host y un WAF que evalúe cada petición antes de que
llegue al backend.

La opción convencional es una cadena de proxies: `nginx` delante de
HAProxy delante del WAF, o ModSecurity como módulo de Apache. Eso multiplica
los puntos de configuración del TLS, los reenvíos de IP real y las
oportunidades de que el enrutado y la inspección diverjan.

## Decisión

**Coraza como motor SPOE de HAProxy**, no como proxy independiente.

```text
cliente ──TLS──► HAProxy ──SPOE──► Coraza (CRS) ──SPOE──► HAProxy decide
                                            │
                                            └── deny ──► 403 al cliente
```

El WAF **no** está en el camino del paquete. HAProxy delega la evaluación
mediante SPOE y recibe la acción de vuelta; la decisión de `deny` la aplica
el propio proxy.

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| nginx + ModSecurity | Añade un salto en el camino crítico y un segundo gestion de certificados. ModSecurity es además más pesado que Coraza |
| Coraza como proxy independiente (`coraza-proxy`) | Funciona, pero duplica la terminación TLS y obliga a reconciliar la IP real en dos puntos |
| HAProxy + módulo WAF | No existe un módulo equivalente a Coraza para HAProxy; el ecosistema está en SPOE |
| Barrido de la request en la aplicación | El backend pasa a ser responsable de su propia protección: cada servicio, cada lenguaje, cada equipo. Además, el backend consume CPU en un ataque |
| Sin WAF, solo IDS | El IDS ve el tráfico pero no puede impedir la petición. La mitigación pasa a ser reactiva |

## Consecuencias

**A favor:**

- **Un solo punto de terminación TLS** y un solo sitio donde se decide la IP
  real del cliente.
- **El WAF no añade latencia estructural**: se evalúa en el mismo hilo de
  HAProxy, con el contexto completo de la petición (cabeceras, cuerpo, URI).
- **La decisión de bloqueo es explícita** y se puede auditar: HAProxy
  responde `403` y anota la acción en la respuesta para depuración.
- **Un solo conjunto de reglas** para todo el tráfico, gestionado con las
  herramientas estándar del WAF (CRS, `ctl:ruleRemoveById`,
  `ctl:ruleRemoveTargetByTag`).
- El WAF deja de ser un componente que hay que mantener *y* que hay que
  posicionar correctamente respecto al proxy.

**En contra:**

- El SPOE **no es un estándar universal**: obliga a que proxy y WAF
  compartan un idioma. Coraza-SPOA es hoy el único motor WAF que lo habla
  bien.
- El WAF hereda las **limitaciones de SPOE**: sin streaming de cuerpo, hay
  que decidir explícitamente si se inspecciona el cuerpo de la petición y
  cuál es el límite de tamaño.
- Dependencia de una pieza con menos ecosystem que nginx+ModSecurity.

**Consecuencia operativa concreta:** los falsos positivos del CRS sobre
peticiones legítimas con JSON en el cuerpo (los *false positives* de SQLi sobre
texto libre) se resuelven con **excepciones acotadas por token**, nunca
deshabilitando reglas globalmente. Ver
[`config/coraza/coraza.conf`](../../config/coraza/coraza.conf).

## Referencia

Configuración: [`config/haproxy/haproxy.cfg`](../../config/haproxy/haproxy.cfg)
y [`config/coraza/coraza.conf`](../../config/coraza/coraza.conf).
