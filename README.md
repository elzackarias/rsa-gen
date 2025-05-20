# 🔐 Los números primos y la criptografía: Implementación de RSA en Python

Este repositorio contiene el código fuente del proyecto final para la materia de **Estructuras Discretas**, titulado *"Los números primos y la criptografía"*. El proyecto incluye una implementación interactiva del algoritmo RSA en Python, con generación de claves, cifrado y descifrado de mensajes, y validación de claves RSA.

## 📘 Descripción

El sistema criptográfico RSA (Rivest-Shamir-Adleman) es uno de los pilares de la criptografía moderna. Basado en la dificultad de factorizar productos de números primos grandes, RSA permite el cifrado de información y la verificación de firmas digitales mediante el uso de claves públicas y privadas.

Este proyecto:

- Implementa la generación de claves RSA utilizando números primos generados mediante el test de Miller-Rabin.
- Permite cifrar y descifrar mensajes con las claves actuales.
- Incluye una interfaz de línea de comandos para validar el funcionamiento de RSA con diferentes llaves.
- Incluye funciones de prueba de primalidad.

---

## 🧪 Funcionalidades

- Generación de claves RSA de tamaño configurable (por ejemplo, 1024 o 2048 bits).
- Cifrado y descifrado de mensajes de texto.
- Validación de mensajes cifrados con claves diferentes (falla controlada).
- Prueba de primalidad con el algoritmo de Miller-Rabin.
- Verificación de correspondencia entre claves públicas y privadas.

---

## 🧩 Estructura del Código

- `es_primo(n, k=5)`: Prueba de primalidad de Miller-Rabin.
- `generar_primo(bits)`: Genera un número primo aleatorio del tamaño deseado.
- `generar_claves(bits)`: Genera las claves pública y privada RSA.
- `cifrar_mensaje(mensaje, clave_publica)`: Cifra un mensaje con la clave pública.
- `descifrar_mensaje(cifrados, clave_privada, clave_publica_original)`: Descifra bloques cifrados.
- `main()`: Menú interactivo para ejecutar y probar las funcionalidades.

---

## 🖥️ Ejecución

Requisitos:
- Python 3.8 o superior

```bash
git clone https://github.com/elzackarias/rsa-gen.git

cd rsa-gen
python rsa-gen.py
