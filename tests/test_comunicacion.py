"""
Pruebas automatizadas para los módulos de comunicación:
1. Canal simulado en memoria.
2. Servidor y cliente mediante Sockets TCP reales en localhost.
"""

import unittest
import time
from src.rsa import ClaveRSA
from src.comunicacion import Emisor, Receptor, CanalSimulado


class TestComunicacion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Primos de 40 cifras genuinos generados por el sistema (LCG semilla 12345)
        cls.p = 2939024496748501956007508882668547624603
        cls.q = 4297540119004976840175189270482921163457
        cls.clave_rsa = ClaveRSA(cls.p, cls.q)

    def test_comunicacion_canal_simulado(self):
        """Verifica el flujo Emisor -> Canal Simulado -> Receptor."""
        receptor = Receptor(self.clave_rsa)
        emisor = Emisor(receptor.clave_publica)
        canal = CanalSimulado(latencia_ms=10)

        mensaje_original = "Mensaje universitario cifrado con RSA y canal simulado: ¡Árbol, Pingüino, Ñandú!"

        # 1. Emisor cifra el mensaje
        payload_cifrado = emisor.cifrar(mensaje_original)
        self.assertIsNotNone(payload_cifrado)

        # 2. Emisor envía a través del canal
        emisor.enviar_por_simulador(canal)

        # 3. Receptor extrae del canal
        payload_recibido = receptor.recibir_de_simulador(canal)
        self.assertIsNotNone(payload_recibido)
        self.assertEqual(payload_recibido, payload_cifrado)

        # 4. Receptor desencripta
        recuperado = receptor.descifrar()
        self.assertEqual(mensaje_original, recuperado)

        # 5. Verificación de integridad
        ok, detalle = receptor.verificar_con_original(mensaje_original)
        self.assertTrue(ok)

    def test_comunicacion_socket_tcp(self):
        """Verifica la transmisión real cliente-servidor por Sockets TCP en localhost."""
        puerto_prueba = 65434
        receptor = Receptor(self.clave_rsa)
        emisor = Emisor(receptor.clave_publica)

        mensaje_original = "Transmisión real por socket TCP: Universidad 2026."

        # Iniciar servidor receptor
        hilo_servidor = receptor.iniciar_servidor_tcp(host="127.0.0.1", puerto=puerto_prueba)
        time.sleep(0.1)  # Breve pausa para asegurar enlace de escucha

        try:
            # Emisor cifra y transmite por socket TCP
            emisor.cifrar(mensaje_original)
            respuesta_ack = emisor.enviar_por_socket_tcp(host="127.0.0.1", puerto=puerto_prueba)
            self.assertIn("ACK", respuesta_ack)

            # Receptor procesa el mensaje recibido
            recuperado = receptor.descifrar()
            self.assertEqual(mensaje_original, recuperado)

            ok, _ = receptor.verificar_con_original(mensaje_original)
            self.assertTrue(ok)
        finally:
            receptor.detener_servidor_tcp()
            time.sleep(0.1)


if __name__ == "__main__":
    unittest.main()
