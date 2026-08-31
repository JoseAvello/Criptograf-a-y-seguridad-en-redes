import sys

def cifrado_cesar(texto: str, corrimiento: int) -> str:
    resultado = []
    corrimiento = corrimiento % 26

    for caracter in texto:
        if caracter.isalpha():
            inicio = ord('A') if caracter.isupper() else ord('a')
            nueva_posicion = (ord(caracter) - inicio + corrimiento) % 26
            resultado.append(chr(inicio + nueva_posicion))
        else:
            resultado.append(caracter)

    return "".join(resultado)

def main():
    # Verifica que se hayan pasado exactamente 2 parámetros (más el nombre del script)
    if len(sys.argv) != 3:
        print("Uso correcto: python3 cesar.py <string_a_cifrar> <corrimiento>")
        sys.exit(1)

    texto_original = sys.argv[1]
    
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("Error: El corrimiento debe ser un número entero.")
        sys.exit(1)

    texto_cifrado = cifrado_cesar(texto_original, desplazamiento)
    print(texto_cifrado)

if __name__ == "__main__":
    main()
