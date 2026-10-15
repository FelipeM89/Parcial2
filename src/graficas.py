"""
Generación de las gráficas del análisis del cifrado RSA.

Ejecuta los experimentos de 'analisis.py', guarda cada figura en PDF
(vectorial, lista para LaTeX) y un resumen numérico en JSON.

Uso:
    python main.py --analisis
"""

import json
import math
import os
import time
from typing import Any, Dict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from . import analisis as an  # noqa: E402

COLORES = {"LCG": "#2f5bd3", "SplitMix": "#c2410c", "SHA-256": "#15803d"}
AZUL, NARANJA, VERDE, GRIS = "#2f5bd3", "#c2410c", "#15803d", "#6b6b70"

plt.rcParams.update({
    "figure.dpi": 120,
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "legend.frameon": False,
})


def _guardar(fig, carpeta: str, nombre: str) -> str:
    ruta = os.path.join(carpeta, nombre)
    fig.tight_layout()
    fig.savefig(ruta)
    plt.close(fig)
    print(f"   [OK] {ruta}")
    return ruta


# ---------------------------------------------------------------------------
# Figuras
# ---------------------------------------------------------------------------

def figura_generacion(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ejes = plt.subplots(2, 2, figsize=(9, 6.4))
    tecnicas = list(datos["tecnicas"])

    # (a) Primos encontrados vs esperados
    ax = ejes[0][0]
    valores = [datos["tecnicas"][t]["primos"] for t in tecnicas]
    barras = ax.bar(tecnicas, valores, color=[COLORES[t] for t in tecnicas], width=0.55)
    ax.axhline(datos["esperados"], color=GRIS, ls="--", lw=1.2,
               label=f"Teorema de los números primos ({datos['esperados']:.0f})")
    ax.bar_label(barras, padding=2)
    ax.set_ylim(0, max(valores) * 1.25)
    ax.set_ylabel("Primos encontrados")
    ax.set_title(f"(a) Primos en {datos['cantidad']:,} números de 40 cifras".replace(",", "."))
    ax.legend(loc="lower right", fontsize=8)

    # (b) Uniformidad de los números generados
    ax = ejes[0][1]
    for t in tecnicas:
        ax.hist(datos["tecnicas"][t]["uniformes"], bins=20, histtype="step", lw=1.6,
                color=COLORES[t], label=t)
    ax.axhline(datos["cantidad"] / 20, color=GRIS, ls="--", lw=1, label="Uniforme ideal")
    ax.set_xlabel("Posición normalizada en $[10^{39}, 10^{40})$")
    ax.set_ylabel("Frecuencia")
    ax.set_title("(b) Distribución de los números generados")
    ax.set_ylim(0, datos["cantidad"] / 20 * 1.4)
    ax.legend(fontsize=8, ncol=2)

    # (c) Huecos entre primos consecutivos vs distribución geométrica
    ax = ejes[1][0]
    huecos = [h for t in tecnicas for h in datos["tecnicas"][t]["huecos"]]
    p = 1 / math.log(10 ** 40)
    ax.hist(huecos, bins=range(0, 500, 25), color=AZUL, alpha=0.75, label="Observado (3 técnicas)")
    xs = list(range(0, 500, 5))
    ax.plot(xs, [len(huecos) * 25 * p * (1 - p) ** x for x in xs], color=NARANJA, lw=1.8,
            label=f"Geométrica, media $\\ln 10^{{40}}\\approx{1 / p:.0f}$")
    ax.set_xlabel("Números generados entre dos primos consecutivos")
    ax.set_ylabel("Frecuencia")
    ax.set_title("(c) Separación entre primos")
    ax.legend(fontsize=8)

    # (d) Último dígito de los primos
    ax = ejes[1][1]
    digitos = [1, 3, 7, 9]
    ancho = 0.25
    for i, t in enumerate(tecnicas):
        ultimos = datos["tecnicas"][t]["ultimo_digito_primos"]
        ax.bar([d + (i - 1) * ancho * 1.6 for d in digitos], [ultimos.count(d) for d in digitos],
               width=ancho * 1.6, color=COLORES[t], label=t)
    total_medio = sum(datos["tecnicas"][t]["primos"] for t in tecnicas) / len(tecnicas)
    ax.axhline(total_medio / 4, color=GRIS, ls="--", lw=1, label="Esperado (1/4)")
    ax.set_xticks(digitos)
    ax.set_xlabel("Último dígito del primo")
    ax.set_ylabel("Cantidad")
    ax.set_title("(d) Los primos solo terminan en 1, 3, 7 o 9")
    ax.legend(fontsize=8, ncol=2)

    _guardar(fig, carpeta, "fig_generacion.pdf")


def figura_tiempos_longitud(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.loglog(datos["longitudes"], datos["cifrar_ms"], "o-", color=AZUL, label="Cifrar (clave pública $e$)")
    ax.loglog(datos["longitudes"], datos["descifrar_ms"], "s-", color=NARANJA, label="Descifrar (clave privada $d$)")
    ax.set_xlabel("Longitud del mensaje (caracteres)")
    ax.set_ylabel("Tiempo (ms)")
    ax.set_title("Tiempo de cifrado y descifrado según la longitud del mensaje")

    ax2 = ax.twinx()
    linea_bloques, = ax2.plot(datos["longitudes"], datos["bloques"], ":", color=GRIS, marker=".",
                              label="Número de bloques (eje derecho)")
    ax2.set_yscale("log")
    ax2.set_ylabel("Bloques de 30 bytes", color=GRIS)
    ax2.tick_params(axis="y", colors=GRIS)
    ax2.grid(False)
    ax2.spines["right"].set_visible(True)

    lineas, etiquetas = ax.get_legend_handles_labels()
    ax.legend(lineas + [linea_bloques], etiquetas + [linea_bloques.get_label()], loc="upper left")
    _guardar(fig, carpeta, "fig_tiempos_longitud.pdf")


def figura_exponenciacion(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 3.6))
    etiquetas = [
        f"Cifrar\n$m^e$ mod $n$\n($e$: {datos['bits_e']} bits)",
        f"Descifrar\n$c^d$ mod $n$\n($d$: {datos['bits_d']} bits)",
        "Descifrar con\nTeorema Chino\ndel Resto",
    ]
    valores = [datos["cifrar_ms"], datos["descifrar_ms"], datos["descifrar_crt_ms"]]
    barras = ax.barh(etiquetas, valores, color=[AZUL, NARANJA, VERDE], height=0.55)
    ax.bar_label(barras, labels=[f"{v * 1000:.1f} µs" for v in valores], padding=4)
    ax.invert_yaxis()
    ax.set_xlim(0, max(valores) * 1.3)
    ax.set_xlabel("Tiempo por bloque (ms)")
    ax.set_title("Costo de una exponenciación modular (un bloque)")
    ax.grid(axis="y", visible=False)
    _guardar(fig, carpeta, "fig_exponenciacion.pdf")


def figura_avalancha(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 3.8))
    bins = [i / 100 for i in range(0, 71)]
    ax.hist(datos["plano"], bins=bins, color=GRIS, alpha=0.8,
            label=f"Texto plano $m$ (media {datos['media_plano'] * 100:.1f} %)")
    ax.hist(datos["cifrado"], bins=bins, color=NARANJA, alpha=0.85,
            label=f"Texto cifrado $c$ (media {datos['media_cifrado'] * 100:.1f} %)")
    ax.axvline(0.5, color=AZUL, ls="--", lw=1.2, label="Ideal: 50 %")
    ax.set_xlabel("Fracción de bits que cambian al modificar 1 carácter")
    ax.set_ylabel("Mensajes")
    ax.set_title(f"Efecto avalancha ({len(datos['cifrado'])} mensajes de un bloque)")
    ax.legend()
    _guardar(fig, carpeta, "fig_avalancha.pdf")


def figura_bytes(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ejes = plt.subplots(1, 2, figsize=(9, 3.6), sharey=False)
    for ax, clave, color, titulo in [
        (ejes[0], "plano", GRIS, "Texto plano"),
        (ejes[1], "cifrado", NARANJA, "Texto cifrado"),
    ]:
        ax.hist(datos[clave], bins=range(0, 257, 4), color=color)
        ax.set_xlim(0, 256)
        ax.set_xlabel("Valor del byte (0-255)")
        ax.set_title(f"{titulo}: entropía {datos['entropia_' + clave]:.2f} bits/byte")
    ejes[0].set_ylabel("Frecuencia")
    _guardar(fig, carpeta, "fig_bytes.pdf")


def figura_escalabilidad(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    x = datos["bits_n"]
    ax.semilogy(x, datos["claves_ms"], "^-", color=VERDE, label="Generar claves (validar $p, q$ y calcular $d$)")
    ax.semilogy(x, datos["descifrar_ms"], "s-", color=NARANJA, label="Descifrar un bloque")
    ax.semilogy(x, datos["cifrar_ms"], "o-", color=AZUL, label="Cifrar un bloque")
    i40 = datos["cifras"].index(40) if 40 in datos["cifras"] else None
    if i40 is not None:
        ax.axvline(x[i40], color=GRIS, ls=":", lw=1)
        ax.annotate("Este proyecto\n($p, q$ de 40 cifras)", (x[i40], ax.get_ylim()[0]),
                    xytext=(6, 12), textcoords="offset points", fontsize=8, color=GRIS)
    ax2 = ax.secondary_xaxis("top", functions=(lambda b: b, lambda b: b))
    ax2.set_xticks(x)
    ax2.set_xticklabels([str(c) for c in datos["cifras"]], fontsize=8)
    ax2.set_xlabel("Cifras de cada primo", fontsize=9)
    ax.set_xlabel("Tamaño de $n$ (bits)")
    ax.set_ylabel("Tiempo (ms, escala log)")
    ax.set_title("Escalabilidad con el tamaño de la clave", pad=10)
    ax.legend(fontsize=8)
    _guardar(fig, carpeta, "fig_escalabilidad.pdf")


def figura_factorizacion(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.2))
    xs, ts = datos["cifras_p"], datos["tiempos_s"]
    ax.semilogy(xs, ts, "o", color=AZUL, ms=7, label="Medido (Pollard-Rho)")

    objetivo = datos["cifras_objetivo"]
    linea_x = list(range(xs[0], objetivo + 1))
    linea_y = [10 ** (datos["intercepto"] + datos["pendiente"] * x) for x in linea_x]
    ax.semilogy(linea_x, linea_y, "--", color=NARANJA,
                label=f"Ajuste: $t \\propto 10^{{{datos['pendiente']:.2f}\\,k}}$  (teoría: $10^{{0.5k}}$)")
    ax.semilogy([objetivo], [datos["segundos_objetivo"]], "*", color=NARANJA, ms=14)
    ax.annotate(f"$p$ de {objetivo} cifras:\n≈ {datos['anios_objetivo']:.1e} años",
                (objetivo, datos["segundos_objetivo"]), xytext=(-120, -10),
                textcoords="offset points", fontsize=9)

    referencias = [(60, "1 minuto"), (3.156e7, "1 año"), (4.35e17, "Edad del universo")]
    for segundos, texto in referencias:
        ax.axhline(segundos, color=GRIS, lw=0.8, ls=":")
        ax.text(xs[0], segundos * 1.6, texto, fontsize=8, color=GRIS)

    ax.set_xlabel("Cifras de cada primo $k$ ($n$ tiene $2k$ cifras)")
    ax.set_ylabel("Tiempo para factorizar $n$ (s)")
    ax.set_title("Romper la clave por fuerza bruta (Pollard-Rho)")
    ax.legend(loc="lower right", fontsize=8)
    _guardar(fig, carpeta, "fig_factorizacion.pdf")


def figura_sensibilidad(datos: Dict[str, Any], carpeta: str) -> None:
    fig, ax = plt.subplots(figsize=(7, 3.4))
    for t, valores in datos.items():
        ax.plot(range(1, len(valores) + 1), valores, lw=1, alpha=0.85, color=COLORES[t],
                label=f"{t} (media {sum(valores) / len(valores):.3f})")
    ax.axhline(0.5, color=GRIS, ls="--", lw=1)
    ax.set_ylim(0.25, 0.75)
    ax.set_xlabel("Número generado $i$")
    ax.set_ylabel("Fracción de bits distintos")
    ax.set_title("Sensibilidad a la condición inicial: semilla $s$ vs $s+1$")
    ax.legend(fontsize=8, ncol=3, loc="upper center")
    _guardar(fig, carpeta, "fig_sensibilidad.pdf")


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

def generar_todo(carpeta: str = os.path.join("informe", "figuras"), texto_corpus: str = "README.md") -> Dict[str, Any]:
    os.makedirs(carpeta, exist_ok=True)
    t_inicio = time.time()
    resumen: Dict[str, Any] = {}

    print("[1/8] Clave de referencia (LCG, semilla 12345)...")
    clave, primos, _ = an.clave_de_referencia()
    clave_ajena = an.ClaveRSA(primos[2], primos[3])
    resumen["clave"] = {"p": str(clave.p), "q": str(clave.q), "n": str(clave.n),
                        "cifras_n": len(str(clave.n)), "bits_n": clave.n.bit_length(),
                        "e": clave.e, "d": str(clave.d)}

    print("[2/8] Generación y primalidad (3 x 10.000)...")
    gen = an.experimento_generacion()
    figura_generacion(gen, carpeta)
    resumen["generacion"] = {
        "esperados": gen["esperados"],
        **{t: {"primos": d["primos"], "huecos_media": sum(d["huecos"]) / len(d["huecos"]),
               "tiempo_generacion_s": d["tiempo_generacion_s"],
               "tiempo_primalidad_s": d["tiempo_primalidad_s"]}
           for t, d in gen["tecnicas"].items()},
    }

    print("[3/8] Tiempos según longitud del mensaje...")
    tl = an.experimento_tiempos_longitud(clave)
    figura_tiempos_longitud(tl, carpeta)
    resumen["tiempos_longitud"] = tl

    print("[4/8] Costo de la exponenciación modular...")
    ex = an.experimento_exponenciacion(clave)
    figura_exponenciacion(ex, carpeta)
    resumen["exponenciacion"] = ex

    print("[5/8] Efecto avalancha y distribución de bytes...")
    av = an.experimento_avalancha(clave)
    figura_avalancha(av, carpeta)
    resumen["avalancha"] = {k: v for k, v in av.items() if k.startswith(("media", "desv"))}

    with open(texto_corpus, encoding="utf-8") as f:
        corpus = f.read()
    by = an.experimento_bytes(clave, corpus)
    figura_bytes(by, carpeta)
    resumen["bytes"] = {k: v for k, v in by.items() if k not in ("plano", "cifrado")}

    print("[6/8] Corrección con 1000 mensajes aleatorios...")
    resumen["correccion"] = an.experimento_correccion(clave, clave_ajena)

    print("[7/8] Escalabilidad y factorización (puede tardar ~1 min)...")
    es = an.experimento_escalabilidad()
    figura_escalabilidad(es, carpeta)
    resumen["escalabilidad"] = es
    fa = an.experimento_factorizacion()
    figura_factorizacion(fa, carpeta)
    resumen["factorizacion"] = fa

    print("[8/8] Sensibilidad a la semilla...")
    se = an.experimento_sensibilidad()
    figura_sensibilidad(se, carpeta)
    resumen["sensibilidad"] = {t: sum(v) / len(v) for t, v in se.items()}

    ruta_json = os.path.join(os.path.dirname(carpeta) or ".", "resultados_analisis.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(resumen, f, indent=2, ensure_ascii=False)

    print(f"\nResumen guardado en {ruta_json}  ({time.time() - t_inicio:.1f} s)")
    return resumen
