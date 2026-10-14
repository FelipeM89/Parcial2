"""
Pruebas automatizadas para el sistema criptográfico RSA.
Verifica:
1. Generación matemática válida de claves con primos de gran tamaño.
2. Cifrado y descifrado exacto con caracteres UTF-8 en español (tildes, eñes, signos, espacios).
3. Rechazo de primos repetidos (p == q) o no primos.
4. Detección de mensajes vacíos o alteraciones en el mensaje descifrado.
"""

import unittest
from src.rsa import ClaveRSA, cifrar_texto, descifrar_texto, verificar_integridad


class TestRSA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Dos números primos de 40 cifras genuinos generados por el sistema (LCG semilla 12345)
        cls.p = 2939024496748501956007508882668547624603
        cls.q = 4297540119004976840175189270482921163457

    def test_generacion_claves(self):
        """Verifica el cálculo de n, phi, e y d."""
        rsa = ClaveRSA(self.p, self.q)
        e, n = rsa.clave_publica
        d, n_priv = rsa.clave_privada

        self.assertEqual(n, n_priv)
        self.assertEqual(n, self.p * self.q)
        phi = (self.p - 1) * (self.q - 1)
        self.assertEqual(rsa.phi, phi)

        # Relación fundamental: (d * e) % phi == 1
        self.assertEqual((d * e) % phi, 1)

    def test_rechazo_primos_iguales(self):
        """RSA debe rechazar p == q por vulnerabilidad matemática."""
        with self.assertRaises(ValueError):
            ClaveRSA(self.p, self.p)

    def test_rechazo_numero_compuesto(self):
        """RSA debe rechazar números que no sean primos."""
        with self.assertRaises(ValueError):
            ClaveRSA(self.p, 100)

    def test_cifrado_y_descifrado_texto_completo(self):
        """
        Verifica el ciclo completo con texto en español:
        espacios, tildes, eñes, signos de interrogación y exclamación.
        """
        rsa = ClaveRSA(self.p, self.q)
        mensajes_prueba = [
            "¡Hola mundo! Este es un mensaje de prueba con acentos: á, é, í, ó, ú, y la letra ñ.",
            "¿Cómo estás? 1234567890 - Criptografía RSA con números primos de 40 cifras.",
            "Texto largo: " + ("El veloz murciélago hindú comía feliz cardillo y kiwi. " * 3),
            "Símbolos especiales: #$%&*()_+=-[]{}|;:,.<>/?¡!¿?~"
        ]

        for original in mensajes_prueba:
            cifrado = cifrar_texto(original, rsa.clave_publica)
            self.assertIn("bloques", cifrado)
            self.assertGreater(len(cifrado["bloques"]), 0)

            recuperado = descifrar_texto(cifrado, rsa.clave_privada)
            self.assertEqual(original, recuperado)

            ok, detalle = verificar_integridad(original, recuperado)
            self.assertTrue(ok)

    def test_mensaje_vacio(self):
        """El cifrador debe rechazar mensajes vacíos."""
        rsa = ClaveRSA(self.p, self.q)
        with self.assertRaises(ValueError):
            cifrar_texto("", rsa.clave_publica)

    def test_deteccion_discrepancia(self):
        """El verificador debe detectar discrepancias entre el texto original y el alterado."""
        original = "Mensaje original secreto"
        alterado = "Mensaje original alterad"
        ok, detalle = verificar_integridad(original, alterado)
        self.assertFalse(ok)
        self.assertIn("Discrepancia detectada", detalle)


if __name__ == "__main__":
    unittest.main()
