"""
Pruebas automatizadas para el módulo de generadores pseudoaleatorios.
Verifica:
1. Tamaño exacto de 40 cifras decimales para los tres algoritmos.
2. Reproducibilidad determinista a partir de una semilla fija.
3. Rechazo de parámetros no válidos (ej. gamma par en SplitMix).
"""

import unittest
from src.generadores import (
    Congruencial,
    Gamma,
    Hash,
    generar_numeros,
    bits_a_numero,
    MINIMO,
    MAXIMO
)


class TestGeneradores(unittest.TestCase):

    def test_rango_40_cifras(self):
        """Comprueba que bits_a_numero genere números en el rango exacto de 40 dígitos."""
        casos = [0, 1, 2**64 - 1, 2**192 - 1, 12345678901234567890]
        for c in casos:
            num = bits_a_numero(c)
            self.assertGreaterEqual(num, MINIMO, f"Número {num} menor a 10^39")
            self.assertLessEqual(num, MAXIMO, f"Número {num} mayor a 10^40 - 1")
            self.assertEqual(len(str(num)), 40, f"El número {num} no tiene 40 cifras decimales")

    def test_generador_congruencial(self):
        """Verifica generación y tamaño con algoritmo Congruencial Lineal (LCG)."""
        semilla = 123456
        cantidad = 20
        numeros = generar_numeros(Congruencial, semilla, cantidad)
        self.assertEqual(len(numeros), cantidad)
        for n in numeros:
            self.assertEqual(len(str(n)), 40)
            self.assertGreaterEqual(n, MINIMO)
            self.assertLessEqual(n, MAXIMO)

        # Reproducibilidad
        numeros_repetidos = generar_numeros(Congruencial, semilla, cantidad)
        self.assertEqual(numeros, numeros_repetidos)

    def test_generador_gamma_splitmix(self):
        """Verifica generación y tamaño con Weyl / SplitMix."""
        semilla = 987654
        cantidad = 20
        numeros = generar_numeros(Gamma, semilla, cantidad)
        self.assertEqual(len(numeros), cantidad)
        for n in numeros:
            self.assertEqual(len(str(n)), 40)

        # Validación de parámetro gamma impar
        with self.assertRaises(ValueError):
            Gamma(semilla=10, gamma=2)

    def test_generador_hash(self):
        """Verifica generación y tamaño con Hash SHA-256."""
        semilla = 55555
        cantidad = 20
        numeros = generar_numeros(Hash, semilla, cantidad)
        self.assertEqual(len(numeros), cantidad)
        for n in numeros:
            self.assertEqual(len(str(n)), 40)

        # Semilla diferente debe generar secuencia diferente
        otra_secuencia = generar_numeros(Hash, semilla + 1, cantidad)
        self.assertNotEqual(numeros, otra_secuencia)


if __name__ == "__main__":
    unittest.main()
