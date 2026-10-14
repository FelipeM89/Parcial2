"""
Módulo de generación de números pseudoaleatorios de 40 cifras.
Implementa tres técnicas distintas conservando la lógica del desarrollo original:
1. Generador Congruencial Lineal (LCG).
2. Generador basado en Gamma mediante Weyl / SplitMix.
3. Generador basado en funciones Hash utilizando SHA-256.
"""

import hashlib
from typing import Dict, Any, List, Type, Tuple

# Constantes para la generación de enteros de 40 cifras decimales exactas
MINIMO = 10 ** 39
MAXIMO = 10 ** 40 - 1
RANGO = MAXIMO - MINIMO + 1

# Se requieren 192 bits (3 bloques de 64 bits) para cubrir el espacio de valores de 40 cifras
BITS_POR_NUMERO = 192


def bits_a_numero(bits: int) -> int:
    """
    Convierte una secuencia de bits a un entero de exactamente 40 cifras decimales,
    dentro del intervalo [10^39, 10^40 - 1].
    """
    return MINIMO + (bits % RANGO)


class Congruencial:
    """
    Generador Congruencial Lineal (LCG).
    Fórmula de recurrencia: X_{n+1} = (a * X_n + c) mod m
    Utiliza parámetros estándar de 64 bits de Knuth/MMIX.
    """

    nombre = "Congruencial lineal (LCG)"
    clave = "lcg"

    parametros_defecto = {
        "a": 6364136223846793005,
        "c": 1442695040888963407,
        "m": 2 ** 64
    }

    def __init__(self, semilla: int, a: int = None, c: int = None, m: int = None):
        params = self.parametros_defecto
        self.a = a if a is not None else params["a"]
        self.c = c if c is not None else params["c"]
        self.m = m if m is not None else params["m"]
        self.x = int(semilla) % self.m

    def siguiente_bloque(self) -> int:
        """Genera un bloque de 64 bits pseudoaleatorios."""
        self.x = (self.a * self.x + self.c) % self.m
        return self.x & 0xFFFFFFFFFFFFFFFF


class Gamma:
    """
    Generador de Weyl con constante de mezcla Gamma (SplitMix).
    Avanza el estado con una constante impar (Gamma de Weyl) y aplica
    transformaciones no lineales de mezcla de bits (bit shifts y multiplicaciones).
    """

    nombre = "Weyl con gamma (SplitMix)"
    clave = "splitmix"

    parametros_defecto = {
        "gamma": 0x9E3779B97F4A7C15
    }

    MASCARA = 0xFFFFFFFFFFFFFFFF

    def __init__(self, semilla: int, gamma: int = None):
        g = gamma if gamma is not None else self.parametros_defecto["gamma"]
        if g % 2 == 0:
            raise ValueError("El parámetro gamma debe ser un número impar.")

        self.estado = int(semilla) & self.MASCARA
        self.gamma = int(g) & self.MASCARA

    def siguiente_bloque(self) -> int:
        """Genera un bloque de 64 bits pseudoaleatorios mediante SplitMix."""
        self.estado = (self.estado + self.gamma) & self.MASCARA

        z = self.estado
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASCARA
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASCARA
        z = z ^ (z >> 31)

        return z


class Hash:
    """
    Generador pseudoaleatorio basado en funciones Hash criptográficas (SHA-256 por defecto).
    Concatena la semilla con un contador monótono y extrae los 8 primeros bytes
    del resumen para formar palabras de 64 bits.
    """

    nombre = "Basado en hash (SHA-256)"
    clave = "hash"

    parametros_defecto = {
        "algoritmo": "sha256"
    }

    def __init__(self, semilla: Any, algoritmo: str = None):
        self.semilla = str(semilla)
        self.algoritmo = algoritmo if algoritmo is not None else self.parametros_defecto["algoritmo"]
        self.contador = 0

    def siguiente_bloque(self) -> int:
        """Genera un bloque de 64 bits pseudoaleatorios a partir del digest hash."""
        self.contador += 1
        mensaje = f"{self.semilla}:{self.contador}".encode("utf-8")
        resumen = hashlib.new(self.algoritmo, mensaje).digest()
        return int.from_bytes(resumen[:8], "big")


TECNICAS: Dict[str, Type] = {
    "1": Congruencial,
    "2": Gamma,
    "3": Hash,
    "lcg": Congruencial,
    "splitmix": Gamma,
    "hash": Hash
}


def obtener_clase_tecnica(identificador: str) -> Type:
    """Obtiene la clase del generador según clave numérica o nombre en minúsculas."""
    id_str = str(identificador).strip().lower()
    if id_str in TECNICAS:
        return TECNICAS[id_str]
    raise ValueError(f"Técnica desconocida: '{identificador}'. Opciones disponibles: {list(TECNICAS.keys())}")


def generar_numeros(tecnica_cls: Type, semilla: int, cantidad: int, parametros: Dict[str, Any] = None) -> List[int]:
    """
    Genera una lista de números pseudoaleatorios de 40 cifras decimales exactas.

    :param tecnica_cls: Clase del generador (Congruencial, Gamma, Hash).
    :param semilla: Semilla inicial para la secuencia.
    :param cantidad: Número total de enteros a generar.
    :param parametros: Diccionario con parámetros opcionales del generador.
    :return: Lista de enteros de 40 cifras.
    """
    if cantidad <= 0:
        raise ValueError("La cantidad de números a generar debe ser mayor a 0.")

    params = parametros or {}
    motor = tecnica_cls(semilla, **params)
    bloques_por_num = BITS_POR_NUMERO // 64  # 192 // 64 = 3 bloques de 64 bits

    numeros = []
    for _ in range(cantidad):
        bits = 0
        for _ in range(bloques_por_num):
            bits = (bits << 64) | motor.siguiente_bloque()
        num = bits_a_numero(bits)
        numeros.append(num)

    return numeros
