#!/usr/bin/env python3
"""
Genera la vista previa social (1280x640) del repositorio.

Un SVG a mano -> PNG con Inkscape. Nada de dependencias de Python:
solo se escribe el SVG y se convierte.
"""
import subprocess
import sys
from pathlib import Path

W, H = 1280, 640
FONT = "Lato"
MONO = "Liberation Mono"

BG_TOP = "#0d1117"
BG_BOT = "#111a2e"
PANEL = "#161b22"
BORDER = "#2d333b"
TEXT = "#e6edf3"
MUTED = "#8b949e"
BLUE = "#58a6ff"
GREEN = "#3fb950"
AMBER = "#d29922"
PURPLE = "#bc8cff"
RED = "#f85149"


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def t(x, y, s, size=16, fill=TEXT, weight="normal", anchor="start",
      family=FONT, spacing=0, opacity=1.0, style=""):
    extra = f' letter-spacing="{spacing}"' if spacing else ""
    op = f' opacity="{opacity}"' if opacity != 1.0 else ""
    st = f' font-style="{style}"' if style else ""
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"'
            f'{extra}{op}{st}>{esc(s)}</text>')


def box(x, y, w, h, label, sub=None, accent=BLUE, mono=False):
    """Caja con borde de acento a la izquierda y etiqueta centrada."""
    o = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" '
         f'fill="{PANEL}" stroke="{BORDER}" stroke-width="1"/>']
    o.append(f'<rect x="{x}" y="{y}" width="3" height="{h}" rx="1.5" fill="{accent}"/>')
    if sub:
        o.append(t(x + w / 2, y + h / 2 - 2, label, 17, TEXT, "bold", "middle",
                   MONO if mono else FONT))
        o.append(t(x + w / 2, y + h / 2 + 19, sub, 12.5, MUTED, "normal", "middle"))
    else:
        o.append(t(x + w / 2, y + h / 2 + 6, label, 17, TEXT, "bold", "middle",
                   MONO if mono else FONT))
    return "".join(o)


def arrow(x, y1, y2, color="#3d444d", label=None):
    o = [f'<line x1="{x}" y1="{y1}" x2="{x}" y2="{y2 - 7}" '
         f'stroke="{color}" stroke-width="1.6"/>',
         f'<path d="M {x - 4} {y2 - 7} L {x} {y2} L {x + 4} {y2 - 7} Z" fill="{color}"/>']
    if label:
        o.append(t(x + 10, (y1 + y2) / 2 + 4, label, 11.5, MUTED, "normal"))
    return "".join(o)


def stat(x, y, value, label, accent):
    return (t(x, y, value, 30, accent, "black") +
            t(x, y + 20, label, 12.5, MUTED))


def build():
    o = []
    # --- fondo ---
    o.append(f'<rect width="{W}" height="{H}" fill="{BG_TOP}"/>')
    o.append(f'<rect width="{W}" height="{H}" fill="url(#g)"/>')
    o.append(
        '<defs>'
        f'<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0" stop-color="{BG_TOP}"/>'
        f'<stop offset="0.55" stop-color="#0f1626"/>'
        f'<stop offset="1" stop-color="{BG_BOT}"/>'
        '</linearGradient>'
        '</defs>'
    )

    # --- filete decorativo superior ---
    o.append(f'<rect x="0" y="0" width="{W}" height="3" fill="{BLUE}"/>')
    o.append(f'<rect x="0" y="0" width="{420}" height="3" fill="{PURPLE}"/>')
    o.append(f'<rect x="0" y="0" width="{140}" height="3" fill="{GREEN}"/>')

    # =====================================================
    # COLUMNA IZQUIERDA: título y cifras
    # =====================================================
    LX = 64
    o.append(t(LX, 104, "PERÍMETRO · OBSERVABILIDAD · DATOS", 12.5, BLUE,
               "bold", spacing=2.4))
    o.append(t(LX, 168, "Homelab", 56, TEXT, "black"))
    o.append(t(LX, 224, "Security Architecture", 56, TEXT, "black"))
    o.append(f'<rect x="{LX}" y="248" width="96" height="3" rx="1.5" fill="{GREEN}"/>')

    o.append(t(LX, 288, "Perímetro con WAF e IDS, bus de eventos, detección", 15.5, MUTED))
    o.append(t(LX, 311, "centralizada con bloqueo de IPs y analítica sobre ClickHouse.", 15.5, MUTED))

    # --- stack en monoespaciado ---
    stack = ["HAProxy", "Coraza", "Suricata", "Kafka", "CrowdSec", "ClickHouse", "Grafana"]
    x = LX
    y = 366
    for i, s in enumerate(stack):
        w = 15 + len(s) * 8.6
        o.append(f'<rect x="{x}" y="{y}" width="{w}" height="26" rx="5" '
                 f'fill="#161b22" stroke="{BORDER}" stroke-width="1"/>')
        o.append(t(x + w / 2, y + 17.5, s, 12.5, MUTED, "normal", "middle", MONO))
        x += w + 7
        if i == 3:
            x = LX
            y += 34

    # --- cifras ---
    o.append(f'<line x1="{LX}" y1="462" x2="{LX + 560}" y2="462" '
             f'stroke="{BORDER}" stroke-width="1"/>')
    o.append(stat(LX, 508, "9,1M", "eventos de seguridad", BLUE))
    o.append(stat(LX + 190, 508, "79,5%", "de ruido eliminado en origen", AMBER))
    o.append(stat(LX + 380, 508, "43", "reglas de detección activas", GREEN))

    # --- pie ---
    o.append(t(LX, 588, "github.com/este314/homelab-security-architecture",
               13.5, MUTED, "normal", family=MONO))

    # =====================================================
    # COLUMNA DERECHA: el diagrama
    # =====================================================
    RX = 700
    RW = 516
    o.append(t(RX, 92, "FLUJO", 11.5, MUTED, "bold", spacing=2.2))

    o.append(box(RX, 108, RW, 76, "HAProxy · Coraza · Suricata",
                 "proxy inverso + WAF + IDS en el perímetro", BLUE))
    o.append(arrow(RX + RW / 2, 184, 214, label="eventos"))

    o.append(box(RX, 214, RW, 62, "Kafka", "bus de eventos, un topic por servicio", PURPLE, mono=True))
    o.append(arrow(RX + 122, 276, 306))
    o.append(arrow(RX + 272 + 122, 276, 306))

    o.append(box(RX, 306, 244, 84, "CrowdSec",
                 "detección central → ban en el borde", GREEN))
    o.append(box(RX + 272, 306, 244, 84, "ClickHouse → Grafana",
                 "histórico, capa semántica y panel SOC", AMBER))

    # --- nota del runtime (pendiente) ---
    o.append(f'<rect x="{RX}" y="410" width="{RW}" height="58" rx="8" '
             f'fill="none" stroke="{BORDER}" stroke-width="1" stroke-dasharray="4 4"/>')
    o.append(t(RX + 18, 436, "eBPF / runtime", 13.5, MUTED, "bold", family=MONO))
    o.append(t(RX + 18, 456, "diseñado, pendiente de despliegue", 12.5, MUTED, "normal",
               style="italic"))

    # ---Panel SOC --- (mini widget)
    o.append(f'<rect x="{RX}" y="486" width="{RW}" height="98" rx="8" '
             f'fill="{PANEL}" stroke="{BORDER}" stroke-width="1"/>')
    o.append(t(RX + 18, 510, "Panel SOC · ciclo de vida del ataque", 13, TEXT, "bold"))
    bars = [0.95, 0.72, 0.88, 0.55, 0.80, 0.42, 0.66, 0.90, 0.60, 0.75,
            0.50, 0.85, 0.68, 0.78, 0.45, 0.92]
    bw, gap = 18, 9
    base_y = 566
    for i, v in enumerate(bars):
        bx = RX + 18 + i * (bw + gap)
        hgt = 44 * v
        col = RED if v > 0.85 else (AMBER if v > 0.65 else BLUE)
        o.append(f'<rect x="{bx}" y="{base_y - hgt}" width="{bw}" height="{hgt}" '
                 f'rx="2" fill="{col}" opacity="0.85"/>')
    o.append(f'<line x1="{RX + 18}" y1="{base_y + 0.5}" x2="{RX + RW - 18}" '
             f'y2="{base_y + 0.5}" stroke="{BORDER}" stroke-width="1"/>')

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}">{("".join(o))}</svg>'
    )


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "social-preview.svg")
    out.write_text(build(), encoding="utf-8")
    print(f"SVG escrito en {out}")
