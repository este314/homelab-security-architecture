# Cómo contribuir

Este repositorio es **documentación de arquitectura más configuraciones de
ejemplo anonimizadas**. Las contribuciones más útiles son las que explican
*por qué* se tomó una decisión, no las que añaden componentes.

## Reglas de estilo

- **Documentación en español**, el código y los identificadores en inglés.
- **Markdown**: una idea por párrafo. Si un bloque supera ~80 líneas, extrae
  el detalle a `docs/` y deja el enlace.
- **Diagramas**: fuente en `docs/diagramas/*.mmd` (Mermaid), exportados a
  `.png`/`.svg`. Si cambias un diagrama, regenera los exportados:

  ```bash
  npx -y @mermaid-js/mermaid-cli -i docs/diagramas/D1-arquitectura.mmd \
      -o docs/diagramas/D1-arquitectura.png -b transparent -w 2400
  ```

- **Configuración**: sin secretos en claro, siempre `${VARIABLE}`. Sin IPs
  ni dominios reales: usa `example.com`, `192.168.10.0/24`, `perimeter-01`.

## Antes de abrir un pull request

```bash
# 1. Validar los diagramas (requiere node >= 20)
for f in docs/diagramas/*.mmd; do
  npx -y @mermaid-js/mermaid-cli -i "$f" -o /dev/null || exit 1
done

# 2. Barrido de secretos (lo que hace el job `secrets` de CI)
gitleaks detect --source . --redact --exit-code 1
```

El CI se encarga de ambos, pero ejecutarlos en local es más rápido.

## Formato de los commits

```text
<tipo>: <asunto en imperativo, <= 72 chars>

<Motivo del cambio en 2-3 líneas. Qué problema resuelve y por qué
esta aproximación y no otra.>

Refs: #<issue>
```

Tipos admitidos: `docs`, `config`, `diagrams`, `ci`, `fix`, `chore`.

## Añadir un componente nuevo

1. Diagrama actualizado (`docs/diagramas/`).
2. Fichero de configuración en `config/` con los valores sensibles como
   variables de entorno.
3. Entrada en la tabla de componentes del `README.md`.
4. ADR en `docs/adr/` si la decisión tiene alternativas descartables.
5. Actualización de `docs/arquitectura.md`.
