"""
Módulo de Análisis Experimental del Cifrado RSA.

Reúne los experimentos que alimentan las gráficas del informe. Cada función
devuelve datos puros (listas y diccionarios), sin depender de matplotlib, de
modo que puedan probarse y reutilizarse:

1. Generación: primos por técnica, uniformidad y separación entre primos.
2. Rendimiento: tiempo de cifrado/descifrado según la longitud del mensaje,
   costo de la exponenciación con e, con d y con el Teorema Chino del Resto.
3. Calidad del cifrado: efecto avalancha y distribución/entropía de bytes.
4. Corrección: ida y vuelta de mensajes aleatorios y rechazo de claves ajenas.
5. Seguridad: escalabilidad con el tamaño de los primos y tiempo de
   factorización de n con Pollard-Rho (extrapolado a 80 cifras).
6. Sensibilidad a la semilla (análogo del efecto mariposa en sistemas caóticos).
"""

import math
import random
import time
from collections import Counter
from typing import Any, Callable, Dict, List, Tuple

from .generadores import Congruencial, Gamma, Hash, MINIMO, RANGO, generar_numeros
from .primalidad import analizar_primalidad, es_primo
from .rsa import ClaveRSA, TAMANIO_BLOQUE_BYTES, cifrar_texto, descifrar_texto

TECNICAS_ANALISIS = [("LCG", Congruencial), ("SplitMix", Gamma), ("SHA-256", Hash)]

ALFABETO = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 .,;:¿?¡!áéíóúÁÉÍÓÚñÑü"
)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def distancia_hamming(a: int, b: int) -> int:
    """Número de bits en que difieren dos enteros."""
    return bin(a ^ b).count("1")


def entropia_bytes(datos: bytes) -> float:
    """Entropía de Shannon en bits por byte (máximo 8)."""
    if not datos:
        return 0.0
    total = len(datos)
    return -sum(c / total * math.log2(c / total) for c in Counter(datos).values())


def cronometrar(funcion: Callable[[], Any], repeticiones: int) -> float:
    """Tiempo medio en milisegundos de ejecutar 'funcion'."""
    inicio = time.perf_counter()
    for _ in range(repeticiones):
        funcion()
    return (time.perf_counter() - inicio) / repeticiones * 1000


def mensaje_aleatorio(rng: random.Random, longitud: int) -> str:
    return "".join(rng.choice(ALFABETO) for _ in range(longitud))


def primo_aleatorio(cifras: int, rng: random.Random) -> int:
    """Busca un primo aleatorio con exactamente 'cifras' dígitos."""
    while True:
        candidato = rng.randrange(10 ** (cifras - 1), 10 ** cifras) | 1
        if es_primo(candidato):
            return candidato


def descifrar_crt(c: int, clave: ClaveRSA) -> int:
    """Descifrado RSA acelerado con el Teorema Chino del Resto."""
    p, q, d = clave.p, clave.q, clave.d
    m1 = pow(c, d % (p - 1), p)
    m2 = pow(c, d % (q - 1), q)
    h = (pow(q, -1, p) * (m1 - m2)) % p
    return m2 + h * q


def clave_de_referencia(semilla: int = 12345, cantidad: int = 10000) -> Tuple[ClaveRSA, List[int], List[int]]:
    """Clave RSA construida con los dos primeros primos del LCG (semilla 12345)."""
    numeros = generar_numeros(Congruencial, semilla, cantidad)
    primos = [n for n, p in zip(numeros, analizar_primalidad(numeros)) if p]
    return ClaveRSA(primos[0], primos[1]), primos, numeros


# ---------------------------------------------------------------------------
# 1. Generación de números y primos
# ---------------------------------------------------------------------------

def experimento_generacion(semilla: int = 12345, cantidad: int = 10000) -> Dict[str, Any]:
    """Primos encontrados, uniformidad y huecos entre primos para cada técnica."""
    esperados = cantidad / math.log(10 ** 40)
    resultados = {"cantidad": cantidad, "esperados": esperados, "tecnicas": {}}

    for nombre, clase in TECNICAS_ANALISIS:
        t0 = time.perf_counter()
        numeros = generar_numeros(clase, semilla, cantidad)
        t_gen = time.perf_counter() - t0

        t0 = time.perf_counter()
        primalidad = analizar_primalidad(numeros)
        t_pri = time.perf_counter() - t0

        indices = [i for i, p in enumerate(primalidad) if p]
        huecos = [b - a for a, b in zip(indices, indices[1:])]
        uniformes = [(n - MINIMO) / RANGO for n in numeros]

        resultados["tecnicas"][nombre] = {
            "primos": len(indices),
            "tiempo_generacion_s": t_gen,
            "tiempo_primalidad_s": t_pri,
            "huecos": huecos,
            "uniformes": uniformes,
            "ultimo_digito_primos": [numeros[i] % 10 for i in indices],
        }

    return resultados


# ---------------------------------------------------------------------------
# 2. Rendimiento
# ---------------------------------------------------------------------------

def experimento_tiempos_longitud(clave: ClaveRSA, longitudes: List[int] = None,
                                 repeticiones: int = 20, semilla: int = 1) -> Dict[str, List]:
    """Tiempo de cifrar y descifrar mensajes de distintas longitudes."""
    longitudes = longitudes or [10, 50, 100, 250, 500, 1000, 2000, 4000]
    rng = random.Random(semilla)
    datos = {"longitudes": longitudes, "bloques": [], "cifrar_ms": [], "descifrar_ms": []}

    for longitud in longitudes:
        mensaje = mensaje_aleatorio(rng, longitud)
        carga = cifrar_texto(mensaje, clave.clave_publica)

        datos["bloques"].append(carga["total_bloques"])
        datos["cifrar_ms"].append(cronometrar(lambda: cifrar_texto(mensaje, clave.clave_publica), repeticiones))
        datos["descifrar_ms"].append(cronometrar(lambda: descifrar_texto(carga, clave.clave_privada), repeticiones))

    return datos


def experimento_exponenciacion(clave: ClaveRSA, repeticiones: int = 2000, semilla: int = 2) -> Dict[str, float]:
    """Costo de una exponenciación modular con e, con d y con d + CRT."""
    rng = random.Random(semilla)
    m = rng.randrange(2, clave.n)
    c = pow(m, clave.e, clave.n)

    return {
        "bits_e": clave.e.bit_length(),
        "unos_e": bin(clave.e).count("1"),
        "bits_d": clave.d.bit_length(),
        "unos_d": bin(clave.d).count("1"),
        "cifrar_ms": cronometrar(lambda: pow(m, clave.e, clave.n), repeticiones),
        "descifrar_ms": cronometrar(lambda: pow(c, clave.d, clave.n), repeticiones),
        "descifrar_crt_ms": cronometrar(lambda: descifrar_crt(c, clave), repeticiones),
        "crt_correcto": descifrar_crt(c, clave) == m,
    }


# ---------------------------------------------------------------------------
# 3. Calidad del cifrado
# ---------------------------------------------------------------------------

def experimento_avalancha(clave: ClaveRSA, muestras: int = 1000, semilla: int = 3) -> Dict[str, Any]:
    """
    Cambia un solo carácter de un mensaje de un bloque y mide cuántos bits
    cambian en el texto plano (m) y en el texto cifrado (c).
    """
    rng = random.Random(semilla)
    bits_n = clave.n.bit_length()
    bits_m = (TAMANIO_BLOQUE_BYTES + 1) * 8
    frac_plano, frac_cifrado = [], []

    for _ in range(muestras):
        # Mensaje ASCII de exactamente un bloque (30 bytes)
        mensaje = "".join(rng.choice(ALFABETO[:62]) for _ in range(TAMANIO_BLOQUE_BYTES))
        pos = rng.randrange(len(mensaje))
        nuevo = rng.choice([ch for ch in "abcdefghijklmnopqrstuvwxyz" if ch != mensaje[pos]])
        modificado = mensaje[:pos] + nuevo + mensaje[pos + 1:]

        c1 = int(cifrar_texto(mensaje, clave.clave_publica)["bloques"][0])
        c2 = int(cifrar_texto(modificado, clave.clave_publica)["bloques"][0])
        m1 = int.from_bytes(bytes([len(mensaje.encode())]) + mensaje.encode(), "big")
        m2 = int.from_bytes(bytes([len(modificado.encode())]) + modificado.encode(), "big")

        frac_plano.append(distancia_hamming(m1, m2) / bits_m)
        frac_cifrado.append(distancia_hamming(c1, c2) / bits_n)

    return {
        "plano": frac_plano,
        "cifrado": frac_cifrado,
        "media_plano": sum(frac_plano) / muestras,
        "media_cifrado": sum(frac_cifrado) / muestras,
        "desv_cifrado": (sum((x - sum(frac_cifrado) / muestras) ** 2 for x in frac_cifrado) / muestras) ** 0.5,
    }


def experimento_bytes(clave: ClaveRSA, texto: str) -> Dict[str, Any]:
    """
    Distribución de bytes del texto plano frente al texto cifrado.
    Del cifrado se omite el byte más significativo de cada bloque, que está
    acotado por n y no es uniforme.
    """
    plano = texto.encode("utf-8")
    carga = cifrar_texto(texto, clave.clave_publica)
    largo = (clave.n.bit_length() + 7) // 8

    cifrado = bytearray()
    for bloque in carga["bloques"]:
        cifrado.extend(int(bloque).to_bytes(largo, "big")[1:])

    return {
        "plano": list(plano),
        "cifrado": list(cifrado),
        "entropia_plano": entropia_bytes(plano),
        "entropia_cifrado": entropia_bytes(bytes(cifrado)),
        "bytes_plano": len(plano),
        "bytes_cifrado": len(cifrado),
        "bloques": carga["total_bloques"],
    }


# ---------------------------------------------------------------------------
# 4. Corrección
# ---------------------------------------------------------------------------

def experimento_correccion(clave: ClaveRSA, clave_ajena: ClaveRSA,
                           muestras: int = 1000, semilla: int = 4) -> Dict[str, Any]:
    """Ida y vuelta con la clave correcta y descifrado con una clave ajena."""
    rng = random.Random(semilla)
    correctos, ajenos_recuperan, ajenos_error = 0, 0, 0
    longitudes = []

    for _ in range(muestras):
        mensaje = mensaje_aleatorio(rng, rng.randint(1, 300))
        longitudes.append(len(mensaje))
        carga = cifrar_texto(mensaje, clave.clave_publica)

        if descifrar_texto(carga, clave.clave_privada) == mensaje:
            correctos += 1

        try:
            if descifrar_texto(carga, clave_ajena.clave_privada) == mensaje:
                ajenos_recuperan += 1
        except ValueError:
            ajenos_error += 1

    return {
        "muestras": muestras,
        "correctos": correctos,
        "ajena_recupera": ajenos_recuperan,
        "ajena_error_decodificacion": ajenos_error,
        "ajena_basura": muestras - ajenos_recuperan - ajenos_error,
        "longitud_media": sum(longitudes) / muestras,
    }


# ---------------------------------------------------------------------------
# 5. Seguridad
# ---------------------------------------------------------------------------

def experimento_escalabilidad(cifras: List[int] = None, repeticiones: int = 200,
                              semilla: int = 5) -> Dict[str, List]:
    """Costo de generar claves, cifrar y descifrar según las cifras de p y q."""
    cifras = cifras or [10, 20, 40, 60, 80, 100, 150]
    rng = random.Random(semilla)
    datos = {"cifras": cifras, "bits_n": [], "claves_ms": [], "cifrar_ms": [], "descifrar_ms": []}

    for k in cifras:
        p, q = primo_aleatorio(k, rng), primo_aleatorio(k, rng)
        while q == p:
            q = primo_aleatorio(k, rng)

        clave = ClaveRSA(p, q)
        m = rng.randrange(2, clave.n)
        c = pow(m, clave.e, clave.n)

        datos["bits_n"].append(clave.n.bit_length())
        datos["claves_ms"].append(cronometrar(lambda: ClaveRSA(p, q), max(5, repeticiones // 20)))
        datos["cifrar_ms"].append(cronometrar(lambda: pow(m, clave.e, clave.n), repeticiones))
        datos["descifrar_ms"].append(cronometrar(lambda: pow(c, clave.d, clave.n), repeticiones))

    return datos


def pollard_rho(n: int, rng: random.Random) -> Tuple[int, int]:
    """
    Factoriza n con Pollard-Rho (variante de Brent).
    Devuelve (factor, iteraciones). Complejidad esperada O(sqrt(p)).
    """
    if n % 2 == 0:
        return 2, 1

    iteraciones = 0
    while True:
        y, c, m = rng.randrange(1, n), rng.randrange(1, n), 128
        g, r, prod = 1, 1, 1

        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    prod = prod * abs(x - y) % n
                    iteraciones += 1
                g = math.gcd(prod, n)
                k += m
            r *= 2

        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
                iteraciones += 1

        if g != n:
            return g, iteraciones


def experimento_factorizacion(cifras: List[int] = None, intentos: int = 5,
                              semilla: int = 6, cifras_objetivo: int = 40) -> Dict[str, Any]:
    """
    Mide el tiempo de romper n = p*q con Pollard-Rho para primos pequeños y
    extrapola (regresión lineal en log10) al tamaño usado en el proyecto.
    """
    cifras = cifras or [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    rng = random.Random(semilla)
    tiempos, iteraciones = [], []

    for k in cifras:
        t_k, it_k = [], []
        for _ in range(intentos):
            p, q = primo_aleatorio(k, rng), primo_aleatorio(k, rng)
            n = p * q
            t0 = time.perf_counter()
            factor, it = pollard_rho(n, rng)
            t_k.append(time.perf_counter() - t0)
            it_k.append(it)
            assert factor in (p, q)
        tiempos.append(sorted(t_k)[len(t_k) // 2])
        iteraciones.append(sorted(it_k)[len(it_k) // 2])

    # Regresión log10(t) = a + b * cifras, usando los puntos más grandes (menos ruido)
    xs = cifras[2:]
    ys = [math.log10(t) for t in tiempos[2:]]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx

    segundos_objetivo = 10 ** (a + b * cifras_objetivo)

    return {
        "cifras_p": cifras,
        "tiempos_s": tiempos,
        "iteraciones": iteraciones,
        "pendiente": b,
        "intercepto": a,
        "cifras_objetivo": cifras_objetivo,
        "segundos_objetivo": segundos_objetivo,
        "anios_objetivo": segundos_objetivo / (365.25 * 24 * 3600),
    }


# ---------------------------------------------------------------------------
# 6. Sensibilidad a la semilla (enfoque de sistemas complejos)
# ---------------------------------------------------------------------------

def experimento_sensibilidad(semilla: int = 12345, cantidad: int = 200) -> Dict[str, List[float]]:
    """
    Fracción de bits distintos entre la secuencia con semilla s y con s + 1,
    número a número, para cada técnica. Un valor cercano a 0.5 indica que una
    perturbación mínima de la condición inicial se amplifica por completo.
    """
    bits = (MINIMO * 10 - 1).bit_length()
    datos = {}
    for nombre, clase in TECNICAS_ANALISIS:
        a = generar_numeros(clase, semilla, cantidad)
        b = generar_numeros(clase, semilla + 1, cantidad)
        datos[nombre] = [distancia_hamming(x, y) / bits for x, y in zip(a, b)]
    return datos
