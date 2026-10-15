"""
Punto de Entrada Principal (Main)
Proyecto Universitario: Máquina Criptográfica RSA con Primos Grandes (40 Cifras).

Uso:
  python main.py           -> Inicia la interfaz gráfica (GUI Tkinter)
  python main.py --cli     -> Ejecuta una demostración académica interactiva completa por terminal
  python main.py --test    -> Ejecuta la suite de pruebas unitarias automatizadas
  python main.py --gen     -> Ejecuta la generación académica de 10.000 números de 40 cifras y guarda el CSV
  python main.py --analisis -> Ejecuta el análisis del cifrado y genera las gráficas del informe (requiere matplotlib)
"""

import sys
import argparse
import time
import os
import unittest

from src.generadores import TECNICAS, Congruencial, Gamma, Hash, generar_numeros
from src.primalidad import (
    analizar_primalidad,
    guardar_resultados_csv,
    cargar_primos_csv,
    seleccionar_dos_primos_distintos
)
from src.rsa import ClaveRSA, cifrar_texto, descifrar_texto, verificar_integridad
from src.comunicacion import Emisor, Receptor, CanalSimulado


def ejecutar_demostracion_cli():
    """Ejecuta una demostración completa paso a paso en consola."""
    print("=" * 75)
    print("MÁQUINA CRIPTOGRÁFICA RSA CON NÚMEROS PRIMOS GRANDES (40 CIFRAS)")
    print("Demostración Académica Universitaria")
    print("=" * 75)

    # -------------------------------------------------------------
    # PARTE 1: GENERACIÓN Y EVALUACIÓN DE PRIMALIDAD
    # -------------------------------------------------------------
    print("\n--- ETAPA 1: GENERACIÓN PSEUDOALEATORIA Y BÚSQUEDA DE PRIMOS (40 CIFRAS) ---")
    print("1. Congruencial Lineal (LCG)")
    print("2. Weyl con Gamma (SplitMix)")
    print("3. Basado en Hash (SHA-256)")

    opcion = input("Selecciona técnica [1]: ").strip() or "1"
    tecnica_cls = TECNICAS.get(opcion, Congruencial)
    semilla_str = input("Ingresa semilla [12345]: ").strip() or "12345"
    cantidad_str = input("Cantidad de números a generar [10000]: ").strip() or "10000"

    semilla = int(semilla_str)
    cantidad = int(cantidad_str)

    print(f"\n[+] Generando {cantidad:,} números de 40 cifras con {tecnica_cls.nombre}...")
    t0 = time.time()
    numeros = generar_numeros(tecnica_cls, semilla, cantidad)
    t_gen = time.time() - t0
    print(f"[OK] {cantidad:,} numeros generados en {t_gen:.2f} s.")

    print("[+] Evaluando primalidad mediante Criba preliminar y Miller-Rabin (12 bases)...")
    t1 = time.time()
    primalidad = analizar_primalidad(numeros)
    t_prim = time.time() - t1
    primos = [n for n, es_p in zip(numeros, primalidad) if es_p]

    print(f"[OK] Primalidad evaluada en {t_prim:.2f} s.")
    print(f"[i] Primos de 40 cifras encontrados: {len(primos):,} de {cantidad:,} ({len(primos)/cantidad*100:.2f}%)")

    ruta_csv = os.path.join("results", f"numeros_{tecnica_cls.__name__.lower()}_{semilla}.csv")
    guardar_resultados_csv(numeros, primalidad, ruta_csv)
    print(f"[OK] Resultados guardados en: {ruta_csv}")

    if len(primos) < 2:
        print("[!] No se encontraron al menos 2 primos con esta configuracion. Intentando con datos precargados...")
        ruta_defecto = os.path.join("results", "primos_ejemplo_40_cifras.csv")
        primos = cargar_primos_csv(ruta_defecto)

    # -------------------------------------------------------------
    # PARTE 2: SELECCIÓN DE PRIMOS Y CONFIGURACIÓN RSA
    # -------------------------------------------------------------
    print("\n--- ETAPA 2: CONFIGURACION MATEMATICA DEL SISTEMA RSA ---")
    p, q = seleccionar_dos_primos_distintos(primos)
    print(f"Primo p ({len(str(p))} cifras): {p}")
    print(f"Primo q ({len(str(q))} cifras): {q}")

    print("\n[+] Calculando claves RSA (modulo n = p * q, phi(n), exponente publico e, privado d)...")
    clave_rsa = ClaveRSA(p, q)
    print(f"[OK] Modulo n ({len(str(clave_rsa.n))} cifras):\n    {clave_rsa.n}")
    print(f"[OK] Exponente publico e: {clave_rsa.e}")
    print(f"[OK] Exponente privado d ({len(str(clave_rsa.d))} cifras):\n    {clave_rsa.d}")

    # -------------------------------------------------------------
    # PARTE 3: EMISOR, CIFRADO, ENVÍO Y DESENCRIPTACIÓN
    # -------------------------------------------------------------
    print("\n--- ETAPA 3: COMUNICACION ENTRE EMISOR Y RECEPTOR ---")
    receptor = Receptor(clave_rsa)
    emisor = Emisor(receptor.clave_publica)
    canal = CanalSimulado(latencia_ms=20)

    mensaje_defecto = "Proyecto de Criptografia: Universidad 2026. Con acentos (a, e, i, o, u) y la letra n."
    mensaje_usuario = input(f"\nEscribe el mensaje a enviar [pulsa Enter para usar ejemplo]:\n'{mensaje_defecto}':\n> ").strip()
    mensaje = mensaje_usuario if mensaje_usuario else mensaje_defecto

    print("\n[EMISOR] Cifrando mensaje con la clave publica del receptor...")
    payload_cifrado = emisor.cifrar(mensaje)
    print(f"[EMISOR] Mensaje cifrado en {payload_cifrado['total_bloques']} bloque(s) numerico(s).")
    print(f"[EMISOR] Primer bloque numerico cifrado:\n    {payload_cifrado['bloques'][0]}")

    print("\n[CANAL] Transmitiendo paquete de datos cifrados al Receptor...")
    emisor.enviar_por_simulador(canal)

    print("\n[RECEPTOR] Paquete recibido del canal.")
    payload_recibido = receptor.recibir_de_simulador(canal)

    print("[RECEPTOR] Desencriptando contenido utilizando su clave privada (d, n)...")
    mensaje_recuperado = receptor.descifrar()

    print("\n--- ETAPA 4: VERIFICACION FINAL DE INTEGRIDAD ---")
    print(f"Mensaje Original  : {mensaje}")
    print(f"Mensaje Recuperado: {mensaje_recuperado}")

    coincide, detalle = receptor.verificar_con_original(mensaje)
    if coincide:
        print("\n" + "=" * 75)
        print("[OK] VERIFICACION EXITOSA: EL MENSAJE RECUPERADO COINCIDE EXACTAMENTE.")
        print("=" * 75)
    else:
        print("\n" + "=" * 75)
        print(f"[ERROR] FALLO DE INTEGRIDAD: {detalle}")
        print("=" * 75)


def ejecutar_pruebas():
    """Ejecuta la suite de pruebas unitarias automatizadas."""
    print("Ejecutando suite de pruebas unitarias en 'tests/'...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=2)
    resultado = runner.run(suite)
    sys.exit(0 if resultado.wasSuccessful() else 1)


def ejecutar_generacion_masiva():
    """Genera 10.000 números con los 3 algoritmos y guarda los resultados."""
    print("=" * 70)
    print("GENERACION ACADEMICA DE 10.000 NUMEROS DE 40 CIFRAS")
    print("=" * 70)
    for nombre, cls in [("LCG", Congruencial), ("SplitMix", Gamma), ("Hash-SHA256", Hash)]:
        print(f"\nProcesando {nombre}...")
        t0 = time.time()
        nums = generar_numeros(cls, 12345, 10000)
        res = analizar_primalidad(nums)
        primos = [n for n, p in zip(nums, res) if p]
        t = time.time() - t0
        ruta = os.path.join("results", f"primos_10k_{nombre.lower().replace('-', '_')}.csv")
        guardar_resultados_csv(nums, res, ruta)
        print(f"[OK] {len(primos)} primos encontrados de 10.000 generados ({t:.2f} s). Guardado en {ruta}")


def ejecutar_analisis():
    """Ejecuta los experimentos de análisis y guarda las gráficas en informe/figuras."""
    print("=" * 70)
    print("ANALISIS EXPERIMENTAL DEL CIFRADO RSA")
    print("=" * 70)
    from src.graficas import generar_todo
    generar_todo()


def main():
    parser = argparse.ArgumentParser(
        description="Máquina Criptográfica RSA con Números Primos Grandes (40 Cifras)"
    )
    parser.add_argument("--cli", action="store_true", help="Ejecutar demostración por terminal en consola")
    parser.add_argument("--test", action="store_true", help="Ejecutar pruebas unitarias automatizadas")
    parser.add_argument("--gen", action="store_true", help="Generar los 10.000 números de 40 cifras y guardar CSV")
    parser.add_argument("--analisis", action="store_true", help="Generar las gráficas del análisis del cifrado")
    parser.add_argument("--gui", action="store_true", help="Iniciar la interfaz gráfica de usuario (por defecto)")

    args = parser.parse_args()

    if args.test:
        ejecutar_pruebas()
    elif args.gen:
        ejecutar_generacion_masiva()
    elif args.analisis:
        ejecutar_analisis()
    elif args.cli:
        ejecutar_demostracion_cli()
    else:
        # Por defecto abre la GUI
        try:
            from src.interfaz import iniciar_interfaz
            iniciar_interfaz()
        except Exception as e:
            print(f"No fue posible iniciar la interfaz gráfica: {e}")
            print("Iniciando modo consola (--cli) como alternativa...")
            ejecutar_demostracion_cli()


if __name__ == "__main__":
    main()
