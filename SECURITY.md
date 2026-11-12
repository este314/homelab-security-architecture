# Security Policy

## Alcance

Este repositorio contiene **documentación y configuraciones de ejemplo
anonimizadas** de un entorno de laboratorio de seguridad. No contiene
credenciales, ni certificados, ni datos de producción.

## Reportar una vulnerabilidad

Si encuentras un problema de seguridad en el material de este repositorio
(configuraciones inseguras por defecto, secretos filtrados, etc.), repórtalo
como *issue* privado o por el canal privado del repositorio, describiendo:

- Qué fichero y línea están afectados.
- Por qué es un problema.
- Una propuesta de corrección.

No abras un issue público para una vulnerabilidad sin resolver.

## Cómo se mantiene la anonimización

Todo el material de `config/` está escrito para ser **demo-native**: los
valores sensibles son variables de entorno (`${...}`) y los identificadores
de infraestructura son genéricos (`example.com`, `192.168.10.0/24`,
`perimeter-01`).

El pipeline de CI ejecuta dos comprobaciones en cada push:

| Job | Qué verifica |
| --- | --- |
| `secrets` | `gitleaks` (detección de secretos por patrón y entropía) + una lista de denegación propia de PII e identificadores de infraestructura |
| `docs` | `markdownlint` y comprobación de enlaces internos rotos |

Si necesitas un valor concreto para un entorno concreto, usa siempre
variables de entorno y `.env` (ignorado por git).

## Credenciales de referencia

Los valores de `.env.example` son marcadores `CHANGE_ME` y no sirven para
nada. Genera secretos reales con:

```bash
openssl rand -hex 24   # API keys y contraseñas de servicio
openssl rand -hex 32   # secretos de alta entropía (tokens)
```
