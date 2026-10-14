"""
Pruebas automatizadas para la evaluación de primalidad con Miller-Rabin y criba.
"""

import unittest
from src.primalidad import (
    primos_hasta,
    es_primo,
    analizar_primalidad,
    seleccionar_dos_primos_distintos
)


class TestPrimalidad(unittest.TestCase):

    def test_criba_pequenos(self):
        """Verifica la generación de primos menores a 50."""
        esperados = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        obtenidos = primos_hasta(50)
        self.assertEqual(obtenidos, esperados)

    def test_primos_y_compuestos_conocidos(self):
        """Verifica la clasificación de números primos y compuestos conocidos."""
        primos_prueba = [2, 3, 5, 7, 13, 997, 1009, 104729, 2147483647]
        for p in primos_prueba:
            self.assertTrue(es_primo(p), f"Falló en identificar primo conocido: {p}")

        compuestos_prueba = [0, 1, 4, 6, 8, 9, 15, 21, 100, 561, 1000, 2147483649]
        for c in compuestos_prueba:
            self.assertFalse(es_primo(c), f"Falló en clasificar como compuesto: {c}")

    def test_numero_grande_compuesto(self):
        """Verifica que el producto de dos números grandes sea catalogado como compuesto."""
        p = 1000000007
        q = 1000000009
        n = p * q
        self.assertFalse(es_primo(n))

    def test_analizar_primalidad_lista(self):
        """Comprueba análisis por lotes."""
        muestra = [2, 4, 5, 9, 11, 15, 17]
        esperado = [True, False, True, False, True, False, True]
        self.assertEqual(analizar_primalidad(muestra), esperado)

    def test_seleccion_dos_primos(self):
        """Verifica la selección y rechazo de primos repetidos o insuficientes."""
        # Caso correcto
        p1, p2 = seleccionar_dos_primos_distintos([17, 17, 19, 23])
        self.assertNotEqual(p1, p2)
        self.assertTrue(es_primo(p1))
        self.assertTrue(es_primo(p2))

        # Caso con primos repetidos insuficientes
        with self.assertRaises(ValueError):
            seleccionar_dos_primos_distintos([17, 17, 17])

        # Caso lista vacía o insuficiente
        with self.assertRaises(ValueError):
            seleccionar_dos_primos_distintos([17])


if __name__ == "__main__":
    unittest.main()
