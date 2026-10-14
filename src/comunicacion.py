"""
Módulo de Comunicación entre Emisor y Receptor.

Proporciona dos modalidades de comunicación explícitas y diferenciadas:
1. Modalidad Simulación Local (Canal en memoria mediante cola thread-safe):
   Permite una demostración académica fluida en una misma interfaz gráfica o consola,
   separando claramente las responsabilidades del Emisor y del Receptor mediante
   un canal independiente de paso de mensajes serializados.

2. Modalidad Red Real (Sockets TCP):
   Implementa una arquitectura cliente-servidor real mediante sockets de red TCP (IPv4).
   El Receptor opera como servidor TCP escuchando en un puerto configurable,
   mientras que el Emisor actúa como cliente TCP conectándose, transmitiendo
   la carga cifrada en formato JSON y recibiendo confirmación (ACK).
"""

import socket
import threading
import json
import time
from typing import Dict, Any, Tuple, Optional, Callable
from queue import Queue, Empty
from .rsa import ClaveRSA, cifrar_texto, descifrar_texto, verificar_integridad


class CanalSimulado:
    """
    Simulador de canal de transmisión de red en memoria.
    Garantiza que el Emisor y el Receptor interactúen únicamente a través
    de un flujo serializado JSON, desacoplando completamente sus estados.
    """

    def __init__(self, latencia_ms: int = 50):
        self._cola: Queue = Queue()
        self.latencia_ms = latencia_ms

    def transmitir(self, datos_json: str) -> None:
        """Deposita un paquete serializado en el canal."""
        if self.latencia_ms > 0:
            time.sleep(self.latencia_ms / 1000.0)
        self._cola.put(datos_json)

    def recibir(self, timeout: float = 2.0) -> Optional[str]:
        """Extrae el siguiente paquete disponible en el canal con tiempo de espera."""
        try:
            return self._cola.get(timeout=timeout)
        except Empty:
            return None


class Emisor:
    """
    Componente Emisor:
    - Conoce únicamente la clave pública del receptor.
    - Cifra mensajes de texto mediante RSA.
    - Transmite el mensaje cifrado hacia el receptor por el canal elegido.
    """

    def __init__(self, clave_publica_receptor: Tuple[int, int]):
        self.clave_publica_receptor = clave_publica_receptor
        self.ultimo_mensaje_plano: Optional[str] = None
        self.ultimo_payload_cifrado: Optional[Dict[str, Any]] = None

    def cifrar(self, mensaje_texto: str) -> Dict[str, Any]:
        """Cifra el mensaje utilizando la clave pública del receptor."""
        self.ultimo_mensaje_plano = mensaje_texto
        self.ultimo_payload_cifrado = cifrar_texto(mensaje_texto, self.clave_publica_receptor)
        return self.ultimo_payload_cifrado

    def enviar_por_simulador(self, canal: CanalSimulado) -> None:
        """Envía el último payload cifrado a través del canal en memoria."""
        if self.ultimo_payload_cifrado is None:
            raise ValueError("No hay ningún mensaje cifrado disponible para enviar.")
        paquete = json.dumps(self.ultimo_payload_cifrado)
        canal.transmitir(paquete)

    def enviar_por_socket_tcp(self, host: str = "127.0.0.1", puerto: int = 65432, timeout: float = 5.0) -> str:
        """
        Envía el payload cifrado a través de un socket TCP real conectado al Receptor.
        Retorna la confirmación (ACK) del receptor.
        """
        if self.ultimo_payload_cifrado is None:
            raise ValueError("No hay ningún mensaje cifrado disponible para enviar.")

        paquete = json.dumps(self.ultimo_payload_cifrado).encode("utf-8")
        # Protocolo simple: 4 bytes de longitud en big-endian seguidos del cuerpo
        cabecera = len(paquete).to_bytes(4, byteorder="big")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, puerto))
            sock.sendall(cabecera + paquete)

            # Recibir respuesta de confirmación
            respuesta = sock.recv(1024).decode("utf-8")
            return respuesta


class Receptor:
    """
    Componente Receptor:
    - Custodia el par de claves RSA (incluyendo la clave privada).
    - Expone su clave pública para que los emisores puedan utilizarla.
    - Recibe el contenido cifrado del canal.
    - Desencripta con su clave privada y recupera el texto original.
    - Comprueba la coincidencia con el mensaje original.
    """

    def __init__(self, clave_rsa: ClaveRSA):
        self.clave_rsa = clave_rsa
        self.ultimo_payload_recibido: Optional[Dict[str, Any]] = None
        self.ultimo_mensaje_recuperado: Optional[str] = None
        self.servidor_tcp_activo = False
        self._servidor_socket: Optional[socket.socket] = None

    @property
    def clave_publica(self) -> Tuple[int, int]:
        """Clave pública compartible (e, n)."""
        return self.clave_rsa.clave_publica

    @property
    def clave_privada(self) -> Tuple[int, int]:
        """Clave privada protegida (d, n)."""
        return self.clave_rsa.clave_privada

    def recibir_de_simulador(self, canal: CanalSimulado, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
        """Recibe un paquete desde el canal de simulación."""
        paquete_str = canal.recibir(timeout=timeout)
        if paquete_str:
            self.ultimo_payload_recibido = json.loads(paquete_str)
            return self.ultimo_payload_recibido
        return None

    def recibir_directo(self, payload: Dict[str, Any]) -> None:
        """Permite depositar directamente un payload recibido."""
        self.ultimo_payload_recibido = payload

    def descifrar(self) -> str:
        """Desencripta el último contenido cifrado recibido utilizando la clave privada."""
        if self.ultimo_payload_recibido is None:
            raise ValueError("No se ha recibido ningún mensaje cifrado para desencriptar.")

        self.ultimo_mensaje_recuperado = descifrar_texto(
            self.ultimo_payload_recibido,
            self.clave_privada
        )
        return self.ultimo_mensaje_recuperado

    def verificar_con_original(self, mensaje_original: str) -> Tuple[bool, str]:
        """Verifica si el mensaje descifrado coincide exactamente con el original."""
        if self.ultimo_mensaje_recuperado is None:
            return False, "Aún no se ha realizado la desencriptación del mensaje."
        return verificar_integridad(mensaje_original, self.ultimo_mensaje_recuperado)

    def iniciar_servidor_tcp(
        self,
        host: str = "127.0.0.1",
        puerto: int = 65432,
        callback_mensaje_recibido: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Inicia un servidor socket TCP en segundo plano para recepción real de mensajes cifrados.
        """
        def _escuchar():
            self._servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._servidor_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._servidor_socket.bind((host, puerto))
            self._servidor_socket.listen(5)
            self.servidor_tcp_activo = True

            while self.servidor_tcp_activo:
                try:
                    self._servidor_socket.settimeout(1.0)
                    cliente_sock, _ = self._servidor_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                with cliente_sock:
                    try:
                        # Leer longitud de 4 bytes
                        raw_len = cliente_sock.recv(4)
                        if not raw_len or len(raw_len) < 4:
                            continue
                        msg_len = int.from_bytes(raw_len, byteorder="big")

                        # Leer cuerpo completo
                        buffer = bytearray()
                        while len(buffer) < msg_len:
                            chunk = cliente_sock.recv(min(4096, msg_len - len(buffer)))
                            if not chunk:
                                break
                            buffer.extend(chunk)

                        payload = json.loads(buffer.decode("utf-8"))
                        self.ultimo_payload_recibido = payload

                        # Confirmar recepción exitosa
                        cliente_sock.sendall(b"ACK: Mensaje cifrado recibido correctamente")

                        if callback_mensaje_recibido:
                            callback_mensaje_recibido(payload)
                    except Exception as err:
                        cliente_sock.sendall(f"ERR: {err}".encode("utf-8"))

        hilo = threading.Thread(target=_escuchar, daemon=True)
        hilo.start()
        return hilo

    def detener_servidor_tcp(self) -> None:
        """Detiene la escucha del socket TCP."""
        self.servidor_tcp_activo = False
        if self._servidor_socket:
            try:
                self._servidor_socket.close()
            except Exception:
                pass
            self._servidor_socket = None
