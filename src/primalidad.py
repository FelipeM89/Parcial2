"""
Módulo de evaluación de primalidad para números enteros grandes (40 cifras).
Conserva la lógica de optimización del notebook original:
1. Filtro rápido con criba de Eratóstenes para primos pequeños (hasta 1000).
2. Test de Miller-Rabin con 12 bases fijas: [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37].

Nota académica y técnica:
Para números del orden de 40 cifras decimales (~133 bits), el test de Miller-Rabin con un conjunto
finito de 12 bases constituye una prueba de PROBABLE PRIMALIDAD (pseudoprimo fuerte).
La probabilidad de que un número compuesto supere las 12 bases independientes es menor a (1/4)^12
(aproximadamente 6 * 10^-8), lo que resulta idóneo para fines didácticos e investigación empírica,
pero no representa una demostración determinista absoluta.
"""

import os
import csv
from typing import List, Tuple, Callable, Optional

# Bases estándar utilizadas en el notebook original
BASES_MILLER_RABIN = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def primos_hasta(limite: int) -> List[int]:
    """
    Genera todos los números primos menores o iguales a 'limite'
    mediante la Criba de Eratóstenes.
    """
    if limite < 2:
        return []

    criba = [True] * (limite + 1)
    criba[0] = criba[1] = False

    for i in range(2, int(limite ** 0.5) + 1):
        if criba[i]:
            for j in range(i * i, limite + 1, i):
                criba[j] = False

    return [i for i, es in enumerate(criba) if es]


# Precomputación de primos pequeños para el filtro rápido preliminar
PRIMOS_PEQUENOS = primos_hasta(1000)


def es_primo(n: int, bases: List[int] = None) -> bool:
    """
    Evalúa si un entero grande 'n' es un probable primo utilizando:
    1. División tentativa por primos menores a 1000.
    2. Test de Miller-Rabin con bases seleccionadas.

    :param n: Entero a evaluar.
    :param bases: Lista de bases para Miller-Rabin (por defecto 12 bases fijas).
    :return: True si es probable primo, False si es compuesto demostrable.
    """
    if n < 2:
        return False

    # Filtro rápido contra primos pequeños
    for p in PRIMOS_PEQUENOS:
        if n == p:
            return True
        if n % p == 0:
            return False

    if bases is None:
        bases = BASES_MILLER_RABIN

    # Descomposición n - 1 = d * 2^r con d impar
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Rondas de Miller-Rabin
    for a in bases:
        if a >= n:
            continue

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        compuesto = True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                compuesto = False
                break

        if compuesto:
            return False

    return True


def analizar_primalidad(numeros: List[int], callback_progreso: Optional[Callable[[int, int], None]] = None) -> List[bool]:
    """
    Evalúa la primalidad de una lista de números. Permite reportar el avance
    mediante una función de callback opcional.
    """
    resultados = []
    total = len(numeros)

    for i, num in enumerate(numeros):
        es_p = es_primo(num)
        resultados.append(es_p)
        if callback_progreso and (i % 250 == 0 or i == total - 1):
            callback_progreso(i + 1, total)

    return resultados


def filtrar_primos(numeros: List[int]) -> List[int]:
    """Devuelve únicamente los números evaluados como primos."""
    return [n for n in numeros if es_primo(n)]


def guardar_resultados_csv(numeros: List[int], primalidad: List[bool], ruta_archivo: str) -> None:
    """
    Guarda los números evaluados en un archivo CSV compatible con el formato del proyecto original.
    """
    os.makedirs(os.path.dirname(os.path.abspath(ruta_archivo)), exist_ok=True)
    with open(ruta_archivo, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["numero", "es_primo"])
        for n, es_p in zip(numeros, primalidad):
            writer.writerow([str(n), "PRIMO" if es_p else "NO PRIMO"])


def cargar_primos_csv(ruta_archivo: str) -> List[int]:
    """
    Lee un archivo de resultados y extrae todos los números catalogados como 'PRIMO'.
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"El archivo de resultados no existe: {ruta_archivo}")

    primos = []
    with open(ruta_archivo, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        encabezado = next(reader, None)
        for fila in reader:
            if not fila:
                continue
            num_str = fila[0].strip()
            estado = fila[1].strip() if len(fila) > 1 else ""
            if estado == "PRIMO" or estado == "True" or not estado:
                try:
                    primos.append(int(num_str))
                except ValueError:
                    continue
    return primos


def seleccionar_dos_primos_distintos(lista_primos: List[int]) -> Tuple[int, int]:
    """
    Selecciona y valida dos números primos distintos a partir de una lista.
    Lanza ValueError descriptivo si no hay suficientes primos válidos y distintos.
    """
    if not lista_primos or len(lista_primos) < 2:
        raise ValueError("Se requieren al menos dos números primos para configurar el sistema RSA.")

    # Filtrar primos válidos distintos mayores que 2
    primos_unicos = []
    for p in lista_primos:
        if p not in primos_unicos and es_primo(p) and p > 2:
            primos_unicos.append(p)
            if len(primos_unicos) == 2:
                break

    if len(primos_unicos) < 2:
        raise ValueError(
            "No se encontraron al menos dos números primos distintos y válidos en los resultados proporcionados."
        )

    return primos_unicos[0], primos_unicos[1]
