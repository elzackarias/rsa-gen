# Author: Jose Zacarias Silberio
# Generador de claves RSA y cifrado/descifrado de mensajes con numeros primos
import random
from math import gcd

def es_primo(n, k=5):
    """
    Determina si un número entero n es primo usando la prueba de primalidad de Miller-Rabin.

    Args:
        n (int): Número a probar si es primo.
        k (int, opcional): Número de iteraciones para la precisión de la prueba. Por defecto es 5.

    Returns:
        bool: True si n probablemente es primo, False si es compuesto.

    Nota:
        Esta es una prueba probabilística. Para números compuestos, la probabilidad de un falso positivo disminuye exponencialmente al aumentar k.
    """
    if n <= 1:
        return False
    elif n <= 3:
        return True
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generar_primo(bits=1024):
    """
    Genera un número primo aleatorio del tamaño de bits especificado.

    Args:
        bits (int): Número de bits para el primo generado. Por defecto es 1024.

    Returns:
        int: Un número primo con la cantidad de bits especificada.

    Notas:
        - La función genera repetidamente números impares aleatorios del tamaño de bits dado
          y los prueba para primalidad usando la función `es_primo` hasta encontrar un primo.
        - El número generado siempre tendrá el bit más alto activado (garantizando el tamaño en bits)
          y será impar.
    """
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if es_primo(p):
            return p

def generar_claves(bits=1024):
    """
    Genera un par de claves pública y privada para el cifrado RSA.

    Args:
        bits (int, optional): Número de bits para el módulo n. Por defecto es 1024.

    Returns:
        tuple: Una tupla que contiene dos tuplas:
            - (e, n): Clave pública.
            - (d, n): Clave privada.

    Nota:
        - Requiere las funciones auxiliares `generar_primo` y `gcd`.
        - El valor de 'e' se inicializa en 65537 y se ajusta si no es coprimo con phi.
    """
    p = generar_primo(bits // 2)
    q = generar_primo(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def cifrar_mensaje(mensaje, clave_publica):
    """
    Cifra un mensaje utilizando la clave pública RSA proporcionada.

    Divide el mensaje en bloques adecuados para el tamaño de la clave, convierte cada bloque a un entero,
    y cifra cada bloque usando la fórmula RSA: c = m^e mod n.

    Args:
        mensaje (str): El mensaje de texto plano a cifrar.
        clave_publica (tuple): Una tupla (e, n) que representa la clave pública RSA.

    Returns:
        list: Una lista de enteros, cada uno correspondiente a un bloque cifrado del mensaje.

    Raises:
        ValueError: Si el mensaje es demasiado grande para la clave o si ocurre algún error durante el cifrado.
    """
    e, n = clave_publica
    bloque_max = (n.bit_length() // 8) - 1
    try:
        bytes_msg = mensaje.encode('utf-8')
        bloques = [bytes_msg[i:i+bloque_max] for i in range(0, len(bytes_msg), bloque_max)]
        cifrados = []
        for bloque in bloques:
            m = int.from_bytes(bloque, 'big')
            if m >= n:
                raise ValueError("Mensaje demasiado grande para la clave")
            c = pow(m, e, n)
            cifrados.append(c)
        return cifrados
    except Exception as e:
        raise ValueError(f"Error al cifrar: {str(e)}")

def descifrar_mensaje(cifrados, clave_privada, clave_publica_original=None):
    """
    Descifra un mensaje cifrado utilizando la clave privada RSA.

    Parámetros:
        cifrados (list[int]): Lista de bloques cifrados (enteros) que representan el mensaje cifrado.
        clave_privada (tuple[int, int]): Tupla (d, n) que representa la clave privada RSA.
        clave_publica_original (tuple[int, int], opcional): Tupla (e, n) de la clave pública original utilizada para cifrar. 
            Si se proporciona, se verifica que el módulo 'n' coincida con el de la clave privada.

    Retorna:
        str: El mensaje descifrado como una cadena de texto.

    Lanza:
        ValueError: Si las llaves no coinciden, si el resultado es vacío, o si ocurre un error durante el descifrado.
    """
    d, n = clave_privada
    if clave_publica_original:
        e_original, n_original = clave_publica_original
        if n != n_original:
            raise ValueError("¡Las llaves no coinciden! El módulo 'n' es diferente")
    try:
        bloques = []
        for c in cifrados:
            m = pow(c, d, n)
            bloque = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            bloques.append(bloque)
        mensaje = b''.join(bloques).decode('utf-8', errors='replace')
        if not mensaje.strip():
            raise ValueError("Resultado vacío - probablemente las llaves son incorrectas")
        return mensaje
    except Exception as e:
        raise ValueError(f"Error al descifrar: {str(e)} - ¿Las llaves no coinciden?")

def mostrar_menu():
    print("\n" + "="*50)
    print(" RSA INTERACTIVO - VALIDACIÓN DE LLAVES")
    print("="*50)
    print("1. Generar nuevas claves")
    print("2. Cifrar mensaje (usar claves actuales)")
    print("3. Descifrar mensaje (usar claves actuales)")
    print("4. Probar descifrado con OTRAS llaves")
    print("5. Ver claves actuales")
    print("6. Probar primalidad")
    print("7. Salir")
    print("="*50)

def main():
    clave_publica = None
    clave_privada = None

    while True:
        mostrar_menu()
        opcion = input("Seleccione una opción (1-7): ")

        if opcion == "1":
            bits = int(input("Tamaño de clave (bits, recomendado 1024-2048): "))
            clave_publica, clave_privada = generar_claves(bits)
            print("\n[✓] Claves generadas!")
            print(f"Clave pública (e, n):\ne = {clave_publica[0]}\nn = {clave_publica[1]}")
            print(f"\nClave privada (d, n):\nd = {clave_privada[0]}\nn = {clave_privada[1]}")

        elif opcion == "2":
            if not clave_publica:
                print("[!] Genere claves primero (opción 1)")
                continue
            mensaje = input("Mensaje a cifrar: ")
            try:
                cifrado = cifrar_mensaje(mensaje, clave_publica)
                print("\n[✓] Mensaje cifrado (bloques):")
                print(", ".join(map(str, cifrado)))
                print("Hexadecimal:", "|".join(hex(b)[2:] for b in cifrado))
            except ValueError as e:
                print(f"[!] {e}")

        elif opcion == "3":
            if not clave_privada:
                print("[!] Genere claves primero (opción 1)")
                continue
            try:
                entrada = input("Ingrese bloques cifrados (separados por comas): ")
                bloques = [int(b.strip()) for b in entrada.split(",")]
                descifrado = descifrar_mensaje(bloques, clave_privada, clave_publica)
                print("\n[✓] Mensaje descifrado:")
                print(descifrado)
            except ValueError as e:
                print(f"\n[✗] Falla de descifrado: {e}")
                print("Posibles causas:")
                print("- Las llaves no corresponden entre sí")
                print("- El mensaje fue cifrado con otras llaves")
                print("- Error en el formato de entrada")

        elif opcion == "4":
            print("\n=== PRUEBA CON LLAVES DIFERENTES ===")
            try:
                e = int(input("Ingrese e (clave pública): "))
                n_publico = int(input("Ingrese n (clave pública): "))
                d = int(input("Ingrese d (clave privada): "))
                n_privado = int(input("Ingrese n (clave privada): "))
                otra_publica = (e, n_publico)
                otra_privada = (d, n_privado)
                entrada = input("Bloques cifrados (separados por comas): ")
                bloques = [int(b.strip()) for b in entrada.split(",")]
                print("\n[?] Probando descifrado...")
                descifrado = descifrar_mensaje(bloques, otra_privada, otra_publica)
                print("\n[✓] Descifrado exitoso con las nuevas llaves:")
                print(descifrado)
                if clave_publica and clave_privada:
                    if (n_publico != clave_publica[1]) or (n_privado != clave_privada[1]):
                        print("\n[!] Advertencia: Estas llaves son diferentes a las actuales")
                        print("El sistema muestra cómo con llaves incorrectas el descifrado falla")
                else:
                    print("\n[!] Nota: No se han generado claves en esta sesión, por lo tanto no se puede comparar.")

            except ValueError as e:
                print(f"\n[✗] Falla de descifrado: {e}")
                print("Esto demuestra que las llaves deben ser parejas válidas")

        elif opcion == "5":
            if clave_publica and clave_privada:
                print("\nClave pública actual (e, n):")
                print(f"e = {clave_publica[0]}")
                print(f"n = {clave_publica[1]}")
                print("n (hex):", hex(clave_publica[1])[2:])
                print("\nClave privada actual (d, n):")
                print(f"d = {clave_privada[0]}")
                print(f"n = {clave_privada[1]}")
            else:
                print("[!] No hay claves generadas")

        elif opcion == "6":
            num = int(input("Número a probar primalidad: "))
            if es_primo(num):
                print(f"\n[✓] {num} ES primo (probabilísticamente)")
            else:
                print(f"\n[✗] {num} NO es primo")

        elif opcion == "7":
            print("\n¡Hasta luego!")
            break

        else:
            print("[!] Opción inválida")

        input("\nPresione Enter para continuar...")

if __name__ == "__main__":
    main()
