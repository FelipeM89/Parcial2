"""
Pruebas automatizadas del módulo de análisis experimental.
Verifica las utilidades (Hamming, entropía, Pollard-Rho, Teorema Chino del Resto)
y que los experimentos principales entreguen resultados coherentes.
"""

import random
import unittest

from src import analisis as an
from src.rsa import ClaveRSA


class TestAnalisis(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.clave = ClaveRSA(2939024496748501956007508882668547624603,
                             4297540119004976840175189270482921163457)

    def test_distancia_hamming(self):
        self.assertEqual(an.distancia_hamming(0b1010, 0b0110), 2)
        self.assertEqual(an.distancia_hamming(7, 7), 0)

    def test_entropia(self):
        self.assertEqual(an.entropia_bytes(b"aaaa"), 0.0)
        self.assertAlmostEqual(an.entropia_bytes(bytes(range(256))), 8.0)

    def test_pollard_rho_factoriza(self):
        rng = random.Random(0)
        p, q = 1000003, 1000033
        factor, _ = an.pollard_rho(p * q, rng)
        self.assertIn(factor, (p, q))

    def test_descifrado_crt(self):
        m = 123456789123456789
        c = pow(m, self.clave.e, self.clave.n)
        self.assertEqual(an.descifrar_crt(c, self.clave), m)

    def test_avalancha_cerca_de_la_mitad(self):
        datos = an.experimento_avalancha(self.clave, muestras=100)
        self.assertGreater(datos["media_cifrado"], 0.45)
        self.assertLess(datos["media_cifrado"], 0.55)

    def test_correccion_total(self):
        ajena = ClaveRSA(an.primo_aleatorio(40, random.Random(1)), an.primo_aleatorio(40, random.Random(2)))
        datos = an.experimento_correccion(self.clave, ajena, muestras=50)
        self.assertEqual(datos["correctos"], 50)
        self.assertEqual(datos["ajena_recupera"], 0)


if __name__ == "__main__":
    unittest.main()
