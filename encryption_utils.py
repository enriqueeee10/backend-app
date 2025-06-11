import base64


def calculate_factor_clave(message_length: int) -> int:
    """
    Calcula el 'factor clave' basado en la longitud del mensaje.
    Corresponde a las reglas de tu lógica VBA.
    """
    l_str = str(message_length)
    suma_digitos = sum(int(digit) for digit in l_str)
    return message_length + suma_digitos


def adapt_clave(key: str, message_length: int) -> str:
    """
    Adapta la clave repitiéndola hasta alcanzar la longitud del mensaje.
    Corresponde a la lógica VBA de 'claveAdaptada'.
    """
    if not key:
        raise ValueError("La clave no puede estar vacía.")
    # Repite la clave y trunca para que coincida con la longitud del mensaje
    return (key * ((message_length // len(key)) + 1))[:message_length]


def custom_encrypt(message: str, key: str) -> str:
    """
    Cifra un mensaje utilizando la lógica personalizada de VBA.
    El resultado es una cadena Base64 del contenido cifrado.
    """
    l = len(message)
    factor_clave = calculate_factor_clave(l)
    clave_adaptada = adapt_clave(key, l)

    # Convertir el mensaje y la clave adaptada a bytes usando 'latin-1' encoding.
    # Esto es crucial para replicar el comportamiento de VBA's Asc() y Chr()
    # que tratan los caracteres como valores de byte individuales (0-255).
    message_bytes = message.encode("latin-1")
    clave_adaptada_bytes = clave_adaptada.encode("latin-1")

    encrypted_bytes = []
    for i in range(l):
        ascii_mensaje = message_bytes[i]
        ascii_clave = clave_adaptada_bytes[i]

        mult_clave = ascii_clave * factor_clave
        mult_i3 = (i + 1) * 3  # VBA es 1-indexado, Python es 0-indexado para 'i'

        suma_total = ascii_mensaje + mult_clave + mult_i3
        valor_final = suma_total % 256  # Modulo 256 para obtener el valor de byte
        encrypted_bytes.append(valor_final)

    # Convertir la lista de enteros (valores de byte) a un objeto 'bytes'
    final_bytes = bytes(encrypted_bytes)
    # Codificar los bytes resultantes en Base64 y luego a una cadena ASCII
    return base64.b64encode(final_bytes).decode("ascii")


def custom_decrypt(encrypted_base64_string: str, key: str) -> str:
    """
    Descifra un mensaje Base64 cifrado utilizando la lógica personalizada de VBA.
    """
    try:
        # Decodificar la cadena Base64 a bytes
        decoded_bytes = base64.b64decode(encrypted_base64_string)
    except Exception as e:
        raise ValueError(f"Cadena Base64 inválida o corrupta: {e}")

    l = len(decoded_bytes)  # Longitud del mensaje original / bytes descifrados

    factor_clave = calculate_factor_clave(l)
    clave_adaptada = adapt_clave(key, l)

    clave_adaptada_bytes = clave_adaptada.encode("latin-1")

    decrypted_bytes = []
    for i in range(l):
        ascii_cifrado = decoded_bytes[i]
        ascii_clave = clave_adaptada_bytes[i]

        mult_clave = ascii_clave * factor_clave
        mult_i3 = (i + 1) * 3  # VBA es 1-indexado, Python es 0-indexado para 'i'

        # La lógica de descifrado en VBA `asciiCifrado - multClave - multI3 + 65536`
        # utiliza `+ 65536` (un múltiplo grande de 256) para asegurar que el resultado antes del `Mod 256`
        # sea positivo. En Python, el operador `%` para números negativos funciona de manera que
        # `(-X) % N` da un resultado positivo `N - (X % N)` (si X es un múltiplo de N, da 0).
        # Por lo tanto, `(valor_a_descifrar - mult_clave - mult_i3) % 256` funcionará correctamente
        # para obtener el valor original.
        valor_final = (ascii_cifrado - mult_clave - mult_i3) % 256
        decrypted_bytes.append(valor_final)

    # Convertir los bytes descifrados de vuelta a una cadena, usando 'latin-1'
    return bytes(decrypted_bytes).decode("latin-1")
