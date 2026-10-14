"""
Interfaz gráfica de usuario (GUI) en Tkinter para el proyecto universitario:
'Diseño e implementación de una máquina para encriptar mensajes usando números primos grandes'.

Estructura por pestañas pedagógicas:
1. Generación y Primalidad: LCG, SplitMix, Hash (SHA-256), 40 cifras, 10.000 números.
2. Claves RSA: Selección de primos p y q, cálculo de n, phi(n), e, d.
3. Comunicación Emisor-Receptor: Cifrado, envío (simulación y sockets TCP), descifrado y verificación.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
from typing import List, Optional

from .generadores import TECNICAS, Congruencial, Gamma, Hash, generar_numeros
from .primalidad import (
    analizar_primalidad,
    guardar_resultados_csv,
    cargar_primos_csv,
    seleccionar_dos_primos_distintos,
    es_primo
)
from .rsa import ClaveRSA, cifrar_texto, descifrar_texto, verificar_integridad
from .comunicacion import Emisor, Receptor, CanalSimulado


class AplicacionCripto(tk.Tk):
    """Ventana principal de la aplicación educativa RSA."""

    def __init__(self):
        super().__init__()
        self.title("Máquina Criptográfica RSA con Primos Grandes (40 Cifras)")
        self.geometry("1060x780")
        self.minsize(980, 680)

        # Estado global de la aplicación
        self.numeros_generados: List[int] = []
        self.primos_encontrados: List[int] = []
        self.p_seleccionado: Optional[int] = None
        self.q_seleccionado: Optional[int] = None
        self.clave_rsa: Optional[ClaveRSA] = None
        self.emisor: Optional[Emisor] = None
        self.receptor: Optional[Receptor] = None
        self.canal_simulado = CanalSimulado(latencia_ms=30)
        self.puerto_tcp = 65432

        # Estilo de la interfaz
        self._configurar_estilos()

        # Construcción de widgets
        self._crear_interfaz()

        # Cargar dataset de respaldo predeterminado si existe
        self._intentar_cargar_datos_iniciales()

    def _configurar_estilos(self):
        """Aplica un tema limpio y moderno para Tkinter."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[12, 6])
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Info.TLabel", font=("Segoe UI", 9))
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))

    def _crear_interfaz(self):
        """Crea el contenedor de pestañas y las vistas principales."""
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_generacion = ttk.Frame(notebook)
        self.tab_rsa = ttk.Frame(notebook)
        self.tab_comunicacion = ttk.Frame(notebook)

        notebook.add(self.tab_generacion, text=" 1. Generación y Primalidad ")
        notebook.add(self.tab_rsa, text=" 2. Configuración Claves RSA ")
        notebook.add(self.tab_comunicacion, text=" 3. Emisor y Receptor ")

        self.notebook = notebook

        self._construir_tab_generacion()
        self._construir_tab_rsa()
        self._construir_tab_comunicacion()

    # =========================================================================
    # PESTAÑA 1: GENERACIÓN Y EVALUACIÓN DE PRIMALIDAD
    # =========================================================================
    def _construir_tab_generacion(self):
        frame = self.tab_generacion

        # Panel superior de configuración
        cfg_frame = ttk.LabelFrame(frame, text=" Configuración de Generación (40 cifras) ", padding=10)
        cfg_frame.pack(fill=tk.X, padx=10, pady=5)

        # Fila 1: Técnica
        ttk.Label(cfg_frame, text="Técnica:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=4)
        self.combo_tecnica = ttk.Combobox(
            cfg_frame,
            values=[
                "1. Congruencial lineal (LCG)",
                "2. Weyl con gamma (SplitMix)",
                "3. Basado en hash (SHA-256)"
            ],
            state="readonly",
            width=32
        )
        self.combo_tecnica.current(0)
        self.combo_tecnica.grid(row=0, column=1, sticky=tk.W, padx=5, pady=4)

        # Fila 1: Semilla
        ttk.Label(cfg_frame, text="Semilla:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=4)
        self.entry_semilla = ttk.Entry(cfg_frame, width=16)
        self.entry_semilla.insert(0, "12345")
        self.entry_semilla.grid(row=0, column=3, sticky=tk.W, padx=5, pady=4)

        # Fila 1: Cantidad
        ttk.Label(cfg_frame, text="Cantidad:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=4)
        self.entry_cantidad = ttk.Entry(cfg_frame, width=12)
        self.entry_cantidad.insert(0, "10000")  # Requisito académico: 10.000 números
        self.entry_cantidad.grid(row=0, column=5, sticky=tk.W, padx=5, pady=4)

        # Botón Generar
        self.btn_generar = ttk.Button(
            cfg_frame,
            text="▶ Generar y Analizar Primalidad",
            style="Accent.TButton",
            command=self._iniciar_generacion_hilo
        )
        self.btn_generar.grid(row=0, column=6, padx=12, pady=4)

        # Barra de progreso
        self.progreso_gen = ttk.Progressbar(cfg_frame, mode="determinate")
        self.progreso_gen.grid(row=1, column=0, columnspan=7, sticky=tk.EW, padx=5, pady=6)

        self.lbl_estado_gen = ttk.Label(cfg_frame, text="Listo para iniciar.", style="Info.TLabel")
        self.lbl_estado_gen.grid(row=2, column=0, columnspan=7, sticky=tk.W, padx=5)

        # Panel central: Estadísticas y lista de primos encontrados
        res_frame = ttk.LabelFrame(frame, text=" Resultados y Números Primos Encontrados ", padding=10)
        res_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Estadísticas resumidas
        stats_box = ttk.Frame(res_frame)
        stats_box.pack(fill=tk.X, pady=4)

        self.lbl_stat_total = ttk.Label(stats_box, text="Generados: 0", font=("Segoe UI", 9, "bold"))
        self.lbl_stat_total.pack(side=tk.LEFT, padx=15)

        self.lbl_stat_primos = ttk.Label(stats_box, text="Primos encontrados: 0", font=("Segoe UI", 9, "bold"), foreground="#007a3d")
        self.lbl_stat_primos.pack(side=tk.LEFT, padx=15)

        self.lbl_stat_tiempo = ttk.Label(stats_box, text="Tiempo: 0.00 s", style="Info.TLabel")
        self.lbl_stat_tiempo.pack(side=tk.LEFT, padx=15)

        # Lista de números primos encontrados
        ttk.Label(res_frame, text="Listado de números primos de 40 cifras detectados:", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(6, 2))
        
        list_container = ttk.Frame(res_frame)
        list_container.pack(fill=tk.BOTH, expand=True)

        self.txt_primos = scrolledtext.ScrolledText(list_container, height=12, font=("Consolas", 10))
        self.txt_primos.pack(fill=tk.BOTH, expand=True)

        # Botones inferiores de acción
        btn_bar = ttk.Frame(frame, padding=6)
        btn_bar.pack(fill=tk.X, padx=10)

        ttk.Button(btn_bar, text="💾 Guardar Resultados (CSV)", command=self._guardar_resultados_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_bar, text="📂 Cargar Primos desde Archivo (CSV)", command=self._cargar_archivo_csv).pack(side=tk.LEFT, padx=5)
        
        self.btn_pasar_a_rsa = ttk.Button(
            btn_bar,
            text="➡ Usar Primos Seleccionados en RSA",
            style="Accent.TButton",
            command=self._transferir_primos_a_rsa
        )
        self.btn_pasar_a_rsa.pack(side=tk.RIGHT, padx=5)

    def _iniciar_generacion_hilo(self):
        """Ejecuta la generación en un hilo independiente para no congelar la GUI."""
        hilo = threading.Thread(target=self._ejecutar_generacion, daemon=True)
        hilo.start()

    def _ejecutar_generacion(self):
        try:
            self.btn_generar.config(state=tk.DISABLED)
            tecnica_idx = self.combo_tecnica.current()
            tecnica_cls = [Congruencial, Gamma, Hash][tecnica_idx]

            try:
                semilla = int(self.entry_semilla.get().strip())
                cantidad = int(self.entry_cantidad.get().strip())
                if cantidad <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error de entrada", "Semilla y cantidad deben ser enteros positivos válidos.")
                return

            self.lbl_estado_gen.config(text=f"Generando {cantidad:,} números de 40 cifras con {tecnica_cls.nombre}...")
            self.progreso_gen.config(value=10)
            self.update_idletasks()

            t0 = time.time()
            numeros = generar_numeros(tecnica_cls, semilla, cantidad)
            t_gen = time.time() - t0

            self.lbl_estado_gen.config(text=f"Generados en {t_gen:.2f} s. Evaluando primalidad con Miller-Rabin...")
            self.progreso_gen.config(value=40)
            self.update_idletasks()

            def progreso_cb(actual, total):
                porcentaje = 40 + int((actual / total) * 55)
                self.progreso_gen.config(value=porcentaje)

            t1 = time.time()
            primalidad = analizar_primalidad(numeros, progreso_cb)
            t_prim = time.time() - t1

            self.numeros_generados = numeros
            self.primos_encontrados = [n for n, es_p in zip(numeros, primalidad) if es_p]

            # Actualizar GUI
            self.progreso_gen.config(value=100)
            tiempo_total = t_gen + t_prim
            self.lbl_stat_total.config(text=f"Generados: {cantidad:,}")
            self.lbl_stat_primos.config(text=f"Primos encontrados: {len(self.primos_encontrados):,}")
            self.lbl_stat_tiempo.config(text=f"Tiempo total: {tiempo_total:.2f} s (Gen: {t_gen:.2f}s, Miller-Rabin: {t_prim:.2f}s)")
            self.lbl_estado_gen.config(text=f"¡Completado! {len(self.primos_encontrados)} números primos de 40 cifras detectados.")

            self.txt_primos.delete("1.0", tk.END)
            for i, p in enumerate(self.primos_encontrados, start=1):
                self.txt_primos.insert(tk.END, f"[{i:03d}] {p}\n")

            if len(self.primos_encontrados) >= 2:
                messagebox.showinfo(
                    "Generación Exitosa",
                    f"Se generaron {cantidad:,} números y se encontraron {len(self.primos_encontrados)} primos de 40 cifras.\n"
                    "Puedes transferirlos directamente a la pestaña de RSA."
                )
            else:
                messagebox.showwarning(
                    "Primos Insuficientes",
                    "Se encontraron menos de 2 primos. Prueba generando una cantidad mayor o cambiando la semilla."
                )

        except Exception as err:
            messagebox.showerror("Error en ejecución", f"Ocurrió un error inesperado:\n{err}")
        finally:
            self.btn_generar.config(state=tk.NORMAL)

    def _guardar_resultados_csv(self):
        if not self.numeros_generados:
            messagebox.showwarning("Sin datos", "Primero debes generar números antes de guardar resultados.")
            return

        ruta = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title="Guardar resultados de primalidad"
        )
        if ruta:
            try:
                primalidad = [n in set(self.primos_encontrados) for n in self.numeros_generados]
                guardar_resultados_csv(self.numeros_generados, primalidad, ruta)
                messagebox.showinfo("Guardado", f"Resultados guardados exitosamente en:\n{ruta}")
            except Exception as err:
                messagebox.showerror("Error al guardar", str(err))

    def _cargar_archivo_csv(self):
        ruta = filedialog.askopenfilename(
            filetypes=[("Archivos CSV", "*.csv"), ("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
            title="Seleccionar archivo con números primos"
        )
        if ruta:
            try:
                primos = cargar_primos_csv(ruta)
                if not primos:
                    messagebox.showwarning("Archivo sin primos", "No se encontraron números catalogados como PRIMO en el archivo.")
                    return
                self.primos_encontrados = primos
                self.txt_primos.delete("1.0", tk.END)
                for i, p in enumerate(primos, start=1):
                    self.txt_primos.insert(tk.END, f"[{i:03d}] {p}\n")
                self.lbl_stat_primos.config(text=f"Primos cargados: {len(primos):,}")
                messagebox.showinfo("Primos Cargados", f"Se cargaron exitosamente {len(primos)} números primos desde el archivo.")
            except Exception as err:
                messagebox.showerror("Error de lectura", f"No se pudo leer el archivo:\n{err}")

    def _intentar_cargar_datos_iniciales(self):
        """Carga automáticamente el archivo de ejemplo si existe."""
        ruta_defecto = os.path.join(os.path.dirname(__file__), "..", "results", "primos_ejemplo_40_cifras.csv")
        if os.path.exists(ruta_defecto):
            try:
                primos = cargar_primos_csv(ruta_defecto)
                if primos:
                    self.primos_encontrados = primos
                    self.txt_primos.delete("1.0", tk.END)
                    for i, p in enumerate(primos[:50], start=1):
                        self.txt_primos.insert(tk.END, f"[{i:03d}] {p}\n")
                    self.lbl_stat_primos.config(text=f"Primos cargados: {len(primos):,}")
                    self.lbl_estado_gen.config(text="Cargados primos de muestra desde 'results/primos_ejemplo_40_cifras.csv'.")
            except Exception:
                pass

    def _transferir_primos_a_rsa(self):
        if len(self.primos_encontrados) < 2:
            messagebox.showwarning("Primos Insuficientes", "Se necesitan al menos 2 números primos encontrados para configurar RSA.")
            return

        try:
            p, q = seleccionar_dos_primos_distintos(self.primos_encontrados)
            self.p_seleccionado = p
            self.q_seleccionado = q

            self.entry_p.delete(0, tk.END)
            self.entry_p.insert(0, str(p))

            self.entry_q.delete(0, tk.END)
            self.entry_q.insert(0, str(q))

            self.notebook.select(self.tab_rsa)
            messagebox.showinfo("Primos Asignados", "Se seleccionaron dos primos distintos de 40 cifras. Ahora pulsa 'Generar Claves RSA'.")
        except Exception as err:
            messagebox.showerror("Error", str(err))

    # =========================================================================
    # PESTAÑA 2: CONFIGURACIÓN Y CLAVES RSA
    # =========================================================================
    def _construir_tab_rsa(self):
        frame = self.tab_rsa

        box_primos = ttk.LabelFrame(frame, text=" Números Primos Seleccionados (De la Primera Parte) ", padding=10)
        box_primos.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(box_primos, text="Primo p (40 cifras):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=4)
        self.entry_p = ttk.Entry(box_primos, width=65, font=("Consolas", 10))
        self.entry_p.grid(row=0, column=1, padx=5, pady=4, sticky=tk.EW)

        ttk.Label(box_primos, text="Primo q (40 cifras):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=4)
        self.entry_q = ttk.Entry(box_primos, width=65, font=("Consolas", 10))
        self.entry_q.grid(row=1, column=1, padx=5, pady=4, sticky=tk.EW)

        btn_generar_claves = ttk.Button(
            box_primos,
            text="🔑 Generar Claves RSA",
            style="Accent.TButton",
            command=self._generar_claves_rsa
        )
        btn_generar_claves.grid(row=2, column=1, sticky=tk.E, padx=5, pady=6)

        # Panel de visualización de parámetros calculados
        box_params = ttk.LabelFrame(frame, text=" Parámetros Matemáticos y Claves Generadas ", padding=10)
        box_params.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Label(box_params, text="Módulo n = p * q (Tamaño ~80 cifras):", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(4, 2))
        self.txt_n = scrolledtext.ScrolledText(box_params, height=3, font=("Consolas", 9))
        self.txt_n.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(box_params, text="Función de Euler phi(n) = (p-1) * (q-1):", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(4, 2))
        self.txt_phi = scrolledtext.ScrolledText(box_params, height=3, font=("Consolas", 9))
        self.txt_phi.pack(fill=tk.X, pady=(0, 6))

        # Fila con exponente público e y exponente privado d
        sub_row = ttk.Frame(box_params)
        sub_row.pack(fill=tk.BOTH, expand=True, pady=4)

        col_e = ttk.LabelFrame(sub_row, text=" Clave Pública (e, n) ", padding=6)
        col_e.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        ttk.Label(col_e, text="Exponente público e:").pack(anchor=tk.W)
        self.entry_e = ttk.Entry(col_e, font=("Consolas", 10))
        self.entry_e.pack(fill=tk.X, pady=4)

        col_d = ttk.LabelFrame(sub_row, text=" Clave Privada (d, n) ", padding=6)
        col_d.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=4)
        ttk.Label(col_d, text="Exponente privado d (inverso modular):").pack(anchor=tk.W)
        self.txt_d = scrolledtext.ScrolledText(col_d, height=3, font=("Consolas", 9))
        self.txt_d.pack(fill=tk.BOTH, expand=True, pady=4)

        # Botón inferior para pasar a la siguiente pestaña
        bottom_bar = ttk.Frame(frame, padding=6)
        bottom_bar.pack(fill=tk.X, padx=10)
        self.btn_ir_a_comunicacion = ttk.Button(
            bottom_bar,
            text="➡ Configurar Emisor y Receptor",
            style="Accent.TButton",
            command=lambda: self.notebook.select(self.tab_comunicacion)
        )
        self.btn_ir_a_comunicacion.pack(side=tk.RIGHT)

    def _generar_claves_rsa(self):
        try:
            p_str = self.entry_p.get().strip()
            q_str = self.entry_q.get().strip()

            if not p_str or not q_str:
                raise ValueError("Debes ingresar o seleccionar ambos números primos p y q.")

            p = int(p_str)
            q = int(q_str)

            self.clave_rsa = ClaveRSA(p, q)
            self.receptor = Receptor(self.clave_rsa)
            self.emisor = Emisor(self.receptor.clave_publica)

            # Mostrar parámetros calculados
            self.txt_n.delete("1.0", tk.END)
            self.txt_n.insert(tk.END, f"{self.clave_rsa.n}\n(Longitud: {len(str(self.clave_rsa.n))} cifras decimales)")

            self.txt_phi.delete("1.0", tk.END)
            self.txt_phi.insert(tk.END, f"{self.clave_rsa.phi}\n(Longitud: {len(str(self.clave_rsa.phi))} cifras decimales)")

            self.entry_e.delete(0, tk.END)
            self.entry_e.insert(0, str(self.clave_rsa.e))

            self.txt_d.delete("1.0", tk.END)
            self.txt_d.insert(tk.END, str(self.clave_rsa.d))

            # Actualizar también los datos en la pestaña de comunicación
            self.txt_emisor_clave_pub.delete("1.0", tk.END)
            self.txt_emisor_clave_pub.insert(
                tk.END,
                f"e = {self.clave_rsa.e}\n\nn (módulo {len(str(self.clave_rsa.n))} cifras):\n{self.clave_rsa.n}"
            )

            self.txt_receptor_clave_priv.delete("1.0", tk.END)
            self.txt_receptor_clave_priv.insert(
                tk.END,
                f"d (exponente privado):\n{self.clave_rsa.d}\n\nn:\n{self.clave_rsa.n}"
            )

            messagebox.showinfo(
                "Claves RSA Generadas",
                f"Par de claves generado con éxito.\nMódulo n: {len(str(self.clave_rsa.n))} cifras.\n"
                "Emisor y Receptor configurados."
            )

        except Exception as err:
            messagebox.showerror("Error al generar claves", str(err))

    # =========================================================================
    # PESTAÑA 3: EMISOR Y RECEPTOR
    # =========================================================================
    def _construir_tab_comunicacion(self):
        frame = self.tab_comunicacion

        # Barra superior con opciones de canal de transmisión
        top_bar = ttk.LabelFrame(frame, text=" Canal de Transmisión ", padding=8)
        top_bar.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(top_bar, text="Modo de Envío:").pack(side=tk.LEFT, padx=5)
        self.var_modo_envio = tk.StringVar(value="simulacion")
        ttk.Radiobutton(top_bar, text="Simulación Local en Memoria (Canal Desacoplado)", variable=self.var_modo_envio, value="simulacion").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(top_bar, text="Red Real Sockets TCP (127.0.0.1)", variable=self.var_modo_envio, value="socket").pack(side=tk.LEFT, padx=10)

        # Panel de dos columnas: Emisor y Receptor
        paneles = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        paneles.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # ==================== COLUMNA EMISOR ====================
        col_emisor = ttk.LabelFrame(paneles, text=" [1] PANEL DEL EMISOR ", padding=10)
        paneles.add(col_emisor, weight=1)

        ttk.Label(col_emisor, text="Clave Pública del Receptor Utilizada para Cifrar (e, n):", style="SubHeader.TLabel").pack(anchor=tk.W)
        self.txt_emisor_clave_pub = scrolledtext.ScrolledText(col_emisor, height=4, font=("Consolas", 8))
        self.txt_emisor_clave_pub.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(col_emisor, text="Mensaje que el Emisor desea enviar:", style="SubHeader.TLabel").pack(anchor=tk.W)
        self.txt_emisor_mensaje = scrolledtext.ScrolledText(col_emisor, height=4, font=("Segoe UI", 10))
        self.txt_emisor_mensaje.insert(tk.END, "Proyecto universitario 2026: ¡Criptografía RSA con primos de 40 cifras y acentos en español (á, é, í, ó, ú, ñ)!")
        self.txt_emisor_mensaje.pack(fill=tk.X, pady=(2, 6))

        btn_cifrar = ttk.Button(col_emisor, text="🔒 Paso 1: Encriptar Mensaje", style="Accent.TButton", command=self._emisor_cifrar)
        btn_cifrar.pack(fill=tk.X, pady=4)

        ttk.Label(col_emisor, text="Mensaje Cifrado (Bloques numéricos c = m^e mod n):", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(4, 2))
        self.txt_emisor_cifrado = scrolledtext.ScrolledText(col_emisor, height=5, font=("Consolas", 8))
        self.txt_emisor_cifrado.pack(fill=tk.BOTH, expand=True, pady=(2, 6))

        self.btn_enviar = ttk.Button(col_emisor, text="📤 Paso 2: Enviar al Receptor", style="Accent.TButton", command=self._emisor_enviar)
        self.btn_enviar.pack(fill=tk.X, pady=4)

        self.lbl_emisor_estado = ttk.Label(col_emisor, text="Listo.", style="Info.TLabel")
        self.lbl_emisor_estado.pack(anchor=tk.W)

        # ==================== COLUMNA RECEPTOR ====================
        col_receptor = ttk.LabelFrame(paneles, text=" [2] PANEL DEL RECEPTOR ", padding=10)
        paneles.add(col_receptor, weight=1)

        ttk.Label(col_receptor, text="Clave Privada del Receptor (d, n):", style="SubHeader.TLabel").pack(anchor=tk.W)
        self.txt_receptor_clave_priv = scrolledtext.ScrolledText(col_receptor, height=4, font=("Consolas", 8))
        self.txt_receptor_clave_priv.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(col_receptor, text="Contenido Cifrado Recibido:", style="SubHeader.TLabel").pack(anchor=tk.W)
        self.txt_receptor_cifrado = scrolledtext.ScrolledText(col_receptor, height=4, font=("Consolas", 8))
        self.txt_receptor_cifrado.pack(fill=tk.X, pady=(2, 6))

        btn_descifrar = ttk.Button(col_receptor, text="🔓 Paso 3: Desencriptar con Clave Privada", style="Accent.TButton", command=self._receptor_descifrar)
        btn_descifrar.pack(fill=tk.X, pady=4)

        ttk.Label(col_receptor, text="Mensaje Original Recuperado por el Receptor:", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(4, 2))
        self.txt_receptor_recuperado = scrolledtext.ScrolledText(col_receptor, height=4, font=("Segoe UI", 10))
        self.txt_receptor_recuperado.pack(fill=tk.BOTH, expand=True, pady=(2, 6))

        # Banner de verificación de integridad
        self.banner_verificacion = tk.Label(
            col_receptor,
            text="Esperando recepción y descifrado...",
            bg="#f0f0f0",
            fg="#555555",
            font=("Segoe UI", 10, "bold"),
            relief=tk.RIDGE,
            padx=10,
            pady=8
        )
        self.banner_verificacion.pack(fill=tk.X, pady=(6, 2))

    def _emisor_cifrar(self):
        if not self.emisor:
            messagebox.showwarning("Faltan claves", "Primero genera las claves en la pestaña 'Configuración Claves RSA'.")
            return

        texto = self.txt_emisor_mensaje.get("1.0", tk.END).rstrip("\r\n")
        if not texto:
            messagebox.showwarning("Mensaje Vacío", "Por favor escribe un mensaje para cifrar.")
            return

        try:
            payload = self.emisor.cifrar(texto)
            self.txt_emisor_cifrado.delete("1.0", tk.END)
            bloques_str = "\n".join(f"Bloque {i+1}: {b}" for i, b in enumerate(payload["bloques"]))
            self.txt_emisor_cifrado.insert(tk.END, bloques_str)
            self.lbl_emisor_estado.config(text=f"Mensaje cifrado con éxito ({payload['total_bloques']} bloques).")
        except Exception as err:
            messagebox.showerror("Error al cifrar", str(err))

    def _emisor_enviar(self):
        if not self.emisor or not self.emisor.ultimo_payload_cifrado:
            messagebox.showwarning("No cifrado", "Primero debes encriptar el mensaje pulsando 'Paso 1: Encriptar Mensaje'.")
            return

        modo = self.var_modo_envio.get()

        if modo == "simulacion":
            try:
                self.emisor.enviar_por_simulador(self.canal_simulado)
                payload_recibido = self.receptor.recibir_de_simulador(self.canal_simulado)
                self.txt_receptor_cifrado.delete("1.0", tk.END)
                bloques_str = "\n".join(f"Bloque {i+1}: {b}" for i, b in enumerate(payload_recibido["bloques"]))
                self.txt_receptor_cifrado.insert(tk.END, bloques_str)

                self.lbl_emisor_estado.config(text="Mensaje enviado con éxito vía Canal Simulado en memoria.")
                messagebox.showinfo("Envío Exitoso", "Mensaje cifrado transmitido y recibido por el Receptor.")
            except Exception as err:
                messagebox.showerror("Error en envío simulado", str(err))

        elif modo == "socket":
            # Iniciar servidor TCP en el receptor si no está corriendo
            if not self.receptor.servidor_tcp_activo:
                self.receptor.iniciar_servidor_tcp(host="127.0.0.1", puerto=self.puerto_tcp)
                time.sleep(0.1)

            try:
                ack = self.emisor.enviar_por_socket_tcp(host="127.0.0.1", puerto=self.puerto_tcp)
                payload = self.receptor.ultimo_payload_recibido
                if payload:
                    self.txt_receptor_cifrado.delete("1.0", tk.END)
                    bloques_str = "\n".join(f"Bloque {i+1}: {b}" for i, b in enumerate(payload["bloques"]))
                    self.txt_receptor_cifrado.insert(tk.END, bloques_str)

                self.lbl_emisor_estado.config(text=f"Enviado por socket TCP (127.0.0.1:{self.puerto_tcp}) - {ack}")
                messagebox.showinfo("Envío TCP Exitoso", f"Mensaje transmitido por red local TCP.\nRespuesta del Receptor: {ack}")
            except Exception as err:
                messagebox.showerror("Error en socket TCP", f"No se pudo conectar al socket receptor:\n{err}")

    def _receptor_descifrar(self):
        if not self.receptor or not self.receptor.ultimo_payload_recibido:
            messagebox.showwarning("Sin mensaje recibido", "El receptor aún no ha recibido ningún mensaje cifrado.")
            return

        try:
            recuperado = self.receptor.descifrar()
            self.txt_receptor_recuperado.delete("1.0", tk.END)
            self.txt_receptor_recuperado.insert(tk.END, recuperado)

            # Comprobar coincidencia exacta con el mensaje original del emisor
            original = self.txt_emisor_mensaje.get("1.0", tk.END).rstrip("\r\n")
            coincide, detalle = self.receptor.verificar_con_original(original)

            if coincide:
                self.banner_verificacion.config(
                    text="✅ ¡VERIFICACIÓN EXITOSA!\nEl mensaje recuperado por el receptor coincide EXACTAMENTE con el original.",
                    bg="#d4edda",
                    fg="#155724"
                )
            else:
                self.banner_verificacion.config(
                    text=f"❌ DISCREPANCIA DETECTADA:\n{detalle}",
                    bg="#f8d7da",
                    fg="#721c24"
                )
        except Exception as err:
            messagebox.showerror("Error al descifrar", str(err))

    def destroy(self):
        """Detiene cualquier servidor activo al cerrar la aplicación."""
        if self.receptor and self.receptor.servidor_tcp_activo:
            self.receptor.detener_servidor_tcp()
        super().destroy()


def iniciar_interfaz():
    """Función para lanzar la aplicación gráfica."""
    app = AplicacionCripto()
    app.mainloop()


if __name__ == "__main__":
    iniciar_interfaz()
