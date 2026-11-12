# ADR-005 · Bouncer en el perímetro, con el estado centralizado

- **Estado:** aceptada
- **Fecha:** 2026-08
- **Ámbito:** aplicación del bloqueo

## Contexto

CrowdSec decide; alguien tiene que ejecutar la decisión. En el diseño
elegido, el nodo que puede bloquear al atacante es **el perímetro**: es donde
entra el tráfico y donde un `DROP` corta la comunicación antes de que llegue
al backend.

Además hay una decisión de diseño previa que condiciona esta: el LAPI es la
autoridad y el bouncer **no guarda estado**. Si el bouncer pierde su estado,
se reconstruye desde el LAPI.

## Decisión

**Un único bouncer de firewall, instalado en el host perimetral**, que aplica
las decisiones con sets de nftables (`crowdsec-blacklists`) y refresca cada
10 segundos.

```text
CrowdSec LAPI ──(pull cada 10 s, API key)──► bouncer ──► set nftables
                                                      │
                                                      └──► chain input/forward
```

El bouncer:

- **No tiene estado propio.** Si se borra, se recrea y se vuelve a conectar.
- **Es idempotente.** Aplicar la misma decisión dos veces no cambia el
  estado.
- **Usa un set, no una regla por IP.** Un `set` de nftables escala a miles de
  entradas con una sola regla de coincidencia, en lugar de miles de reglas.
- **Trabaja con `DROP`, no con `REJECT`.** `DROP` no responde al atacante: no
  le confirma que existe un bloqueo, lo que impide el sondeo adaptativo.

## Alternativas descartadas

| Alternativa | Por qué se descartó |
|---|---|
| Bouncer `REJECT` (respuesta activa) | Un `REJECT` con `RST`/`ICMP` confirma al atacante que su IP está bloqueada. Facilita enumerar el rango bloqueado |
| `iptables` en lugar de `nftables` | `iptables` es la API legacy; `nftables` es la actual, más eficiente y con sets nativos |
| Un bouncer por nodo | Duplica el estado de bloqueo y multiplica el coste. El tráfico de un atacante que llega por otra ruta no se bloquearía |
| HAProxy con lista de IPs bloqueadas | El bloqueo dejaría de ser de red (L3/L4) y pasaría a ser de aplicación (L7). Un atacante que no llegue a HAProxy no se bloquea |
| Bouncer SPOE de CrowdSec | Interesante para un demo: el ban es visible en la respuesta y no requiere `NET_ADMIN`. En producción, el `DROP` de red es más difícil de evadir |

## Consecuencias

**A favor:**

- **El bloqueo ocurre antes de consumir cualquier recurso del backend.**
  Una IP baneada no llega a la aplicación.
- **Coste marginal despreciable**: un set de nftables y un proceso que
  duerme 10 s entre iteraciones.
- **Visible en el perímetro.** El operador puede verificar el estado del
  bloqueo con `nft list set crowdsec-blacklists`.
- **Restaurable**: si el set se pierde, el bouncer lo repuebla en el siguiente
  refresco (≤ 10 s).
- El bouncer cubre **todas las rutas** que entran por ese host, no sólo la
  que pasa por un virtual host concreto.

**En contra:**

- **Requiere privilegios** (`CAP_NET_ADMIN`) y acceso al subsistema de
  red. Es un componente privilegiado en el host más expuesto.
- **La ventana de aplicación es de hasta 10 s.** Una decisión tarda ese
  tiempo en llegar al set. Reducir el intervalo aumenta la carga del LAPI.
- **El `DROP` es invisible para el atacante y para el operador.** En un
  panel, un `DROP` y una petición que nunca llegó son indistinguibles: por
  eso el histórico de decisiones de CrowdSec es imprescindible para
  reconstruir qué pasó. El panel SOC lo resuelve correlacionando ambos
  registros.
- Si el set se corrompe, puede bloquear tráfico legítimo. El `runbook.md`
describe la purga.

## Evidencia

El histórico registra **24.100.100 decisiones**, con 759 decisiones de
`http-probing` sobre 225 IPs distintas y 335 de `suricata-major-severity`
sobre 208 IPs.
