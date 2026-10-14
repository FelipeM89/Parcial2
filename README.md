# Diseño e Implementación de una Máquina para Encriptar Mensajes Usando Números Primos Grandes

## 1. Nombre del proyecto
**Máquina Criptográfica RSA Educativa basada en Generación de Números Primos Grandes de 40 Cifras.**

---

## 2. Descripción
Este proyecto universitario desarrolla una solución integral de software que aborda dos fases esenciales de las ciencias de la computación y la criptografía:
1. La **generación determinista de números enteros pseudoaleatorios de gran escala (40 cifras decimales)** mediante tres algoritmos distintos, junto con la detección rigurosa de números primos utilizando el test de Miller-Rabin asistido por criba previa.
2. El **diseño y construcción de una máquina criptográfica educativa basada en el algoritmo asimétrico RSA**, que reutiliza de forma auténtica los primos encontrados en la primera etapa para implementar un flujo completo de comunicación segura entre dos entidades diferenciadas: un **Emisor** y un **Receptor**.

---

## 3. Problema que resuelve
- **Generación en gran escala:** Genera y procesa lotes de números enteros en el rango exacto de 40 cifras decimales ($10^{39} \le n \le 10^{40}-1$).
- **Identificación empírica de primos:** Analiza la primalidad en muestras masivas (como el requisito académico de 10.000 números) comparando los resultados experimentales con el Teorema de los Números Primos ($N / \ln(10^{40})$).
- **Demostración transparente de RSA:** Elimina la "caja negra" del cifrado mostrando paso a paso el cálculo de las claves $(e, d, n, \phi(n))$, el cifrado modular por bloques, la transmisión del mensaje cifrado y la recuperación verificable del texto en español sin pérdida de caracteres, acentos o espacios.

---

## 4. Características principales
- **Tres técnicas de generación pseudoaleatoria:**
  1. *Congruencial Lineal (LCG)* con parámetros de 64 bits (Knuth/MMIX).
  2. *Weyl con constante Gamma (SplitMix)* con desplazamientos de bits y multiplicaciones de mezcla.
  3. *Generador basado en Hash criptográfico* utilizando resúmenes SHA-256.
- **Rango exacto de 40 cifras:** Agrupación de 192 bits (3 bloques de 64 bits) proyectados al rango $[10^{39}, 10^{40}-1]$.
- **Evaluación optimizada de primalidad:** Filtro preliminar con criba de Eratóstenes (hasta 1.000) y test de Miller-Rabin con 12 bases deterministas.
- **Motor RSA robusto y pedagógico:** Validación de condiciones matemáticas ($p \neq q$, ambos primos, $p > 1, q > 1$), cálculo exacto del inverso modular mediante el Algoritmo Extendido de Euclides y codificación UTF-8 en bloques seguros ($m < n$).
- **Dos modalidades de comunicación entre Emisor y Receptor:**
  1. *Simulación local en memoria:* Desacople total mediante cola thread-safe de paquetes serializados JSON.
  2. *Transmisión en red real por Sockets TCP:* Servidor receptor escuchando en puerto local y cliente emisor transmitiendo paquetes en red IPv4.
- **Interfaz gráfica moderna e intuitiva:** Construida en Tkinter con pestañas interactivas, barras de progreso y verificación visual de integridad.

---

## 5. Tecnologías utilizadas
- **Lenguaje:** Python 3.8+ (probado y verificado en Python 3.11).
- **Biblioteca Estándar de Python:**
  - `hashlib` (resumen criptográfico SHA-256).
  - `math` (funciones de teoría de números y logaritmos).
  - `time` (medición de rendimiento de generación y primalidad).
  - `socket` y `threading` (servidor y cliente TCP para comunicación en red).
  - `queue` (canal desacoplado de simulación).
  - `csv` y `json` (persistencia y serialización de datos).
  - `tkinter` y `tkinter.ttk` (interfaz gráfica de usuario).
  - `unittest` (suite de pruebas automatizadas).
- **Herramientas de testing:** `pytest` (opcional).

---

## 6. Requisitos previos
- Disponer de **Python 3.8 o superior** instalado en el sistema.
- En sistemas Linux, asegurarse de contar con soporte de Tkinter (`sudo apt-get install python3-tk`). En Windows y macOS viene incluido por defecto con el instalador oficial de Python.

---

## 7. Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/FelipeM89/Parcial2.git
   cd Parcial2
   ```

2. **Crear y activar un entorno virtual (opcional pero recomendado):**
   - En Windows (PowerShell):
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - En Linux / macOS:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Instalar dependencias opcionales de desarrollo:**
   ```bash
   pip install -r requirements.txt
   ```
   *(Nota: Toda la aplicación funciona con la librería estándar de Python sin requerir librerías externas obligatorias).*

---

## 8. Cómo ejecutar

Desde la carpeta raíz del proyecto (`proyecto-encriptacion-primos`):

- **Para iniciar la Interfaz Gráfica (GUI):**
  ```bash
  python main.py
  ```
  *(o también: `python main.py --gui`)*

- **Para ejecutar la Demostración Completa por Terminal (Consola):**
  ```bash
  python main.py --cli
  ```

- **Para generar la prueba académica de 10.000 números con los 3 métodos:**
  ```bash
  python main.py --gen
  ```

- **Para ejecutar la suite de pruebas unitarias:**
  ```bash
  python main.py --test
  ```

---

## 9. Cómo utilizarlo paso a paso

1. **Paso 1: Generación y Primalidad**
   - Abre la aplicación (`python main.py`).
   - En la pestaña **1. Generación y Primalidad**, selecciona la técnica deseada (LCG, SplitMix o SHA-256).
   - Ajusta la semilla (ej. `12345`) y la cantidad (por defecto `10000`).
   - Pulsa **"Generar y Analizar Primalidad"**.
   - Observa en pantalla el tiempo de ejecución, la cantidad de primos de 40 cifras encontrados y la lista detallada.
   - Pulsa **"Usar Primos Seleccionados en RSA"** para transferir automáticamente dos primos distintos al sistema criptográfico.

2. **Paso 2: Generación de Claves RSA**
   - En la pestaña **2. Configuración Claves RSA**, revisa los valores de $p$ y $q$.
   - Pulsa **"Generar Claves RSA"**.
   - El sistema validará matemáticamente que ambos números sean primos distintos y calculará el módulo $n$ (alrededor de 80 cifras), la función $\phi(n)$, el exponente público $e = 65537$ y el exponente privado $d$.

3. **Paso 3: Cifrado, Envío y Recepción**
   - Pasa a la pestaña **3. Emisor y Receptor**.
   - Selecciona el modo de envío: **Simulación Local** o **Sockets TCP**.
   - En el panel del **Emisor**, redacta tu mensaje (con acentos, eñes, signos y espacios).
   - Pulsa **"Paso 1: Encriptar Mensaje"** para observar los bloques numéricos $c = m^e \pmod n$.
   - Pulsa **"Paso 2: Enviar al Receptor"**.
   - En el panel del **Receptor**, pulsa **"Paso 3: Desencriptar con Clave Privada"**.
   - Comprueba en el recuadro inferior que el mensaje original y el recuperado coinciden de manera exacta, visualizando el banner verde de verificación.

---

## 10. Cómo funciona internamente

### Generación de 40 Cifras
Para garantizar que cada número tenga exactamente 40 cifras ($10^{39} \le n < 10^{40}$):
- Se generan 192 bits (tres bloques de 64 bits mediante LCG, SplitMix o SHA-256).
- Se aplica la transformación de intervalo:
  $$n = 10^{39} + (\text{bits} \pmod{10^{40} - 10^{39}})$$

### Evaluación de Primalidad (Miller-Rabin)
- Primero se evalúa divisibilidad directa entre primos pequeños ($p \le 1000$).
- Si no tiene divisores triviales, se descompone $n - 1 = d \cdot 2^r$ y se evalúa el test con 12 bases fijas: $[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]$.
- Si el número supera todas las rondas, se clasifica como probable primo.

### Criptografía RSA
1. **Módulo:** $n = p \times q$. Con $p$ y $q$ de 40 cifras, $n$ posee entre 79 y 80 cifras decimales ($n > 2^{260}$).
2. **Función de Euler:** $\phi(n) = (p - 1) \times (q - 1)$.
3. **Exponente público:** $e = 65537$ (o el menor impar coprimo con $\phi(n)$).
4. **Exponente privado:** $d \equiv e^{-1} \pmod{\phi(n)}$, obtenido con el Algoritmo de Euclides Extendido.
5. **Cifrado en bloques UTF-8:** El mensaje se convierte a bytes UTF-8 y se empaqueta en bloques de 30 bytes precedidos por su byte de longitud. Dado que $256^{31} < 10^{79} < n$, se garantiza matemáticamente que cada bloque numérico $m < n$.
6. **Operaciones modulares:**
   - Cifrado: $c = m^e \pmod n$.
   - Descifrado: $m = c^d \pmod n$.

---

## 11. Modalidades de comunicación

El proyecto implementa dos mecanismos claros y diferenciados:

1. **Canal Simulado en Memoria (`CanalSimulado`):**
   - Utiliza una cola thread-safe (`queue.Queue`) para transferir los paquetes JSON con una latencia configurable.
   - El Emisor y el Receptor no comparten variables de texto; el Emisor solo accede a la clave pública $(e, n)$ y el Receptor únicamente a la clave privada $(d, n)$.
2. **Comunicación en Red mediante Sockets TCP (`ServidorReceptorTCP` y `ClienteEmisorTCP`):**
   - El Receptor abre un socket servidor TCP en la dirección local de loopback `127.0.0.1:65432`.
   - La transmisión se realiza entre procesos diferenciados dentro del mismo computador (o en red local si se configura la IP correspondiente).
   - El Emisor se conecta a través del socket de red, transmite la trama con la longitud y el payload JSON, y recibe confirmación `ACK`.

---

## 12. Pruebas automatizadas

Para ejecutar las 17 pruebas unitarias automatizadas:
```bash
python -m unittest discover -s tests -v
```
o directamente con el parámetro:
```bash
python main.py --test
```

Las pruebas verifican:
- Rango exacto de 40 cifras en los generadores.
- Determinismo y reproducibilidad por semilla.
- Criba de Eratóstenes y test de Miller-Rabin con primos y compuestos conocidos.
- Rechazo de primos repetidos ($p = q$) o números no primos en RSA.
- Cifrado y descifrado exacto de caracteres en español (espacios, tildes, signos, eñes).
- Detección de mensajes vacíos o discrepancias en la verificación.
- Comunicación punto a punto con canal simulado y con sockets TCP reales.

---

## 13. Estructura del repositorio

```text
proyecto-encriptacion-primos/
├── README.md                      # Documentación completa del proyecto
├── requirements.txt               # Especificación de dependencias
├── .gitignore                     # Filtros para Git y temporales
├── main.py                        # Punto de entrada principal (GUI, CLI, Tests, Gen)
├── src/                           # Código fuente modular
│   ├── __init__.py                # Inicializador del paquete
│   ├── generadores.py             # Implementación de los 3 generadores pseudoaleatorios
│   ├── primalidad.py              # Criba de Eratóstenes y test de Miller-Rabin
│   ├── rsa.py                     # Motor matemático RSA, cifrado y descifrado por bloques
│   ├── comunicacion.py            # Componentes Emisor, Receptor, Canal Simulado y Sockets TCP
│   └── interfaz.py                # Interfaz gráfica interactiva en Tkinter
├── tests/                         # Suite de pruebas unitarias
│   ├── __init__.py
│   ├── test_generadores.py        # Pruebas de generadores de 40 cifras
│   ├── test_primalidad.py         # Pruebas de evaluación de primalidad
│   ├── test_rsa.py                # Pruebas del cifrado asimétrico RSA
│   └── test_comunicacion.py       # Pruebas de transmisión por canal y sockets TCP
├── notebooks/
│   └── notebook_original.ipynb    # Cuaderno Jupyter original del trabajo de base
└── results/
    ├── .gitkeep                   # Mantenimiento de la carpeta en control de versiones
    └── primos_ejemplo_40_cifras.csv # Muestra precargada con primos auténticos de 40 cifras
```

---

## 14. Consideraciones y limitaciones académicas
- **Propósito Educativo:** Este software está diseñado con fines de investigación académica y demostración docente de los principios matemáticos de RSA y generadores pseudoaleatorios. No debe emplearse como criptosistema en entornos de producción comercial ni para proteger información sensible.
- **Naturaleza probabilística de Miller-Rabin:** Para números enteros de 40 cifras ($\approx 10^{40}$), el test de Miller-Rabin con 12 bases fijas garantiza que los números encontrados son *probables primos fuertes*. La probabilidad de falso positivo es matemáticamente despreciable ($< 4^{-12} \approx 6 \times 10^{-8}$), pero no constituye una prueba analítica determinista absoluta.
- **Generadores Pseudoaleatorios vs. Generadores Criptográficos (CSPRNG):** Algoritmos como LCG y SplitMix están diseñados para simulación y distribución estadística rápida; en criptografía de producción real se utilizan fuentes de entropía física del sistema operativo (`/dev/urandom` o `secrets`).
