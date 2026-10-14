"""
Módulo del Sistema Criptográfico Educativo RSA con Primos Grandes.

Implementación pedagógica y matemáticamente rigurosa de RSA:
1. Validación estricta de condiciones matemáticas: p != q, p y q primos, p > 1, q > 1.
2. Cálculo de los parámetros fundamentales:
   - Módulo: n = p * q
   - Función indicatriz de Euler: phi(n) = (p - 1) * (q - 1)
   - Exponente público: e coprimo con phi(n) (por defecto 65537)
   - Exponente privado: d tal que (d * e) = 1 mod phi(n)
3. Cifrado y descifrado por bloques numéricos para texto UTF-8 completo
   (garantizando m < n en cada bloque y preservando tildes, eñes, espacios y signos).
4. Verificación automática de integridad entre mensaje original y recuperado.
"""

import math
import json
from typing import Tuple, List, Dict, Any
from .primalidad import es_primo


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Algoritmo de Euclides Extendido.
    Calcula g = mcd(a, b) y los coeficientes de Bézout (x, y) tales que:
    a * x + b * y = g
    """
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def inverso_modular(e: int, phi: int) -> int:
    """
    Calcula el inverso modular de 'e' módulo 'phi' usando el algoritmo de Euclides extendido.
    (d * e) % phi == 1
    """
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError(f"El exponente e={e} no tiene inverso modular módulo phi (mcd={g} != 1).")
    return x % phi


def seleccionar_exponente_publico(phi: int) -> int:
    """
    Selecciona un exponente público 'e' adecuado que sea coprimo con phi(n).
    Comienza con 65537 (estándar F4 de Fermat). Si no es coprimo, busca el siguiente impar coprimo.
    """
    candidatos = [65537, 3, 5, 17, 257]
    for c in candidatos:
        if 1 < c < phi and math.gcd(c, phi) == 1:
            return c

    # Búsqueda secuencial de respaldo
    e = 65539
    while e < phi:
        if math.gcd(e, phi) == 1:
            return e
        e += 2

    raise ValueError("No se encontró un exponente público coprimo con phi(n).")


class ClaveRSA:
    """Representa un par de claves pública y privada de RSA junto con sus parámetros."""

    def __init__(self, p: int, q: int, e: int = None):
        self.p = p
        self.q = q
        self.validar_primos(p, q)

        # Cálculo de parámetros matemáticos
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

        # Selección de e y cálculo de d
        if e is not None:
            if math.gcd(e, self.phi) != 1:
                raise ValueError(f"El exponente especificado e={e} no es coprimo con phi(n).")
            self.e = e
        else:
            self.e = seleccionar_exponente_publico(self.phi)

        self.d = inverso_modular(self.e, self.phi)

    @staticmethod
    def validar_primos(p: int, q: int):
        """Valida que p y q cumplan los requisitos formales para RSA."""
        if not isinstance(p, int) or not isinstance(q, int):
            raise TypeError("Los valores p y q deben ser números enteros.")
        if p <= 1 or q <= 1:
            raise ValueError("Los números primos deben ser estrictamente mayores que 1.")
        if p == q:
            raise ValueError(
                "Inseguridad matemática: p y q deben ser primos distintos. "
                "Si p == q, n = p^2 y la factorización es trivial."
            )
        if not es_primo(p):
            raise ValueError(f"El valor p={str(p)[:12]}... no supera el test de primalidad.")
        if not es_primo(q):
            raise ValueError(f"El valor q={str(q)[:12]}... no supera el test de primalidad.")

    @property
    def clave_publica(self) -> Tuple[int, int]:
        """Devuelve la tupla (e, n)."""
        return self.e, self.n

    @property
    def clave_privada(self) -> Tuple[int, int]:
        """Devuelve la tupla (d, n)."""
        return self.d, self.n

    def resumen_matematico(self) -> Dict[str, Any]:
        """Devuelve un diccionario estructurado con los parámetros del sistema."""
        return {
            "p": self.p,
            "q": self.q,
            "cifras_p": len(str(self.p)),
            "cifras_q": len(str(self.q)),
            "n": self.n,
            "cifras_n": len(str(self.n)),
            "phi_n": self.phi,
            "e": self.e,
            "d": self.d,
            "cifras_d": len(str(self.d))
        }


# Tamaño máximo seguro por bloque de texto (30 bytes -> máximo 240 bits < 10^79)
TAMANIO_BLOQUE_BYTES = 30


def cifrar_texto(mensaje: str, clave_publica: Tuple[int, int]) -> Dict[str, Any]:
    """
    Cifra un texto arbitrario en formato UTF-8 utilizando la clave pública (e, n).
    Divide los bytes en bloques de longitud segura TAMANIO_BLOQUE_BYTES, garantizando
    que el valor numérico m de cada bloque sea estrictamente menor que n (m < n).

    Se antepone a cada bloque un byte con su longitud real, lo que permite reconstruir
    con exactitud absoluta cualquier secuencia de bytes (incluyendo ceros iniciales o tildes).

    :param mensaje: Cadena de texto a cifrar (soporta tildes, signos, ñ, etc.).
    :param clave_publica: Tupla (e, n).
    :return: Diccionario con la carga cifrada estructurada.
    """
    if not isinstance(mensaje, str):
        raise TypeError("El mensaje debe ser una cadena de texto (str).")
    if len(mensaje) == 0:
        raise ValueError("El mensaje no puede estar vacío.")

    e, n = clave_publica
    datos_bytes = mensaje.encode("utf-8")

    bloques_cifrados = []
    # Fragmentar en bloques de máximo TAMANIO_BLOQUE_BYTES
    for i in range(0, len(datos_bytes), TAMANIO_BLOQUE_BYTES):
        chunk = datos_bytes[i:i + TAMANIO_BLOQUE_BYTES]
        # Estructura del bloque con prefijo de longitud: [len_chunk (1 byte)] + [chunk (k bytes)]
        bloque_enmarcado = bytes([len(chunk)]) + chunk
        m = int.from_bytes(bloque_enmarcado, byteorder="big")

        if m >= n:
            raise ValueError(f"Error de bloque: el valor numérico del bloque ({m}) excede el módulo n.")

        # Cifrado modular RSA: c = m^e mod n
        c = pow(m, e, n)
        bloques_cifrados.append(str(c))

    return {
        "formato": "RSA-EDUCATIVO-40-CIFRAS",
        "total_bloques": len(bloques_cifrados),
        "longitud_bytes_original": len(datos_bytes),
        "bloques": bloques_cifrados,
        "clave_publica_usada": {"e": str(e), "n": str(n)}
    }


def descifrar_texto(carga_cifrada: Dict[str, Any], clave_privada: Tuple[int, int]) -> str:
    """
    Descifra un payload estructurado cifrado con RSA utilizando la clave privada (d, n).

    :param carga_cifrada: Diccionario con los bloques cifrados.
    :param clave_privada: Tupla (d, n).
    :return: Texto original completamente recuperado en UTF-8.
    """
    d, n = clave_privada

    if not isinstance(carga_cifrada, dict) or "bloques" not in carga_cifrada:
        raise ValueError("Formato de carga cifrada inválido. Se esperaba un diccionario con campo 'bloques'.")

    bloques = carga_cifrada["bloques"]
    if not bloques:
        raise ValueError("La carga cifrada no contiene bloques para descifrar.")

    bytes_recuperados = bytearray()
    for bloque_str in bloques:
        c = int(bloque_str)
        # Descifrado modular RSA: m = c^d mod n
        m = pow(c, d, n)

        # Convertir m de vuelta a bytes
        num_bytes = (m.bit_length() + 7) // 8
        if num_bytes == 0:
            num_bytes = 1
        bloque_enmarcado = m.to_bytes(num_bytes, byteorder="big")

        # El primer byte indica la longitud real del chunk
        longitud_chunk = bloque_enmarcado[0]
        chunk = bloque_enmarcado[1:1 + longitud_chunk]
        bytes_recuperados.extend(chunk)

    try:
        return bytes_recuperados.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValueError(
            f"Error al decodificar el mensaje descifrado a UTF-8: {err}. "
            "Es probable que la clave privada no corresponda a la clave pública utilizada."
        )


def verificar_integridad(original: str, recuperado: str) -> Tuple[bool, str]:
    """
    Comprueba de manera estricta que el mensaje recuperado coincida carácter por carácter
    con el mensaje original.
    """
    if original == recuperado:
        return True, f"Verificación exitosa: Mensaje íntegro y exacto ({len(original)} caracteres)."

    len_o, len_r = len(original), len(recuperado)
    detalle = f"Discrepancia detectada: Longitud original={len_o}, recuperada={len_r}."
    return False, detalle
