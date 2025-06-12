import base64


# Common helper functions for message encryption/decryption (from previous turn)
def _calculate_factor_clave_message(message_length: int) -> int:
    """
    Calcula el 'factor clave' para el cifrado/descifrado de MENSAJES
    basado en la longitud del mensaje.
    """
    l_str = str(message_length)
    suma_digitos = sum(int(digit) for digit in l_str)
    return message_length + suma_digitos


def _adapt_clave_message(key: str, target_length: int) -> str:
    """
    Adapta la clave (para mensajes) repitiéndola hasta alcanzar la longitud del mensaje.
    """
    if not key:
        raise ValueError("La clave para el mensaje no puede estar vacía.")
    return (key * ((target_length // len(key)) + 1))[:target_length]


def custom_encrypt_message(message: str, key: str) -> str:
    """
    Cifra un mensaje utilizando la lógica personalizada de VBA.
    El resultado es una cadena Base64 del contenido cifrado.
    """
    l = len(message)
    factor_clave = _calculate_factor_clave_message(l)
    clave_adaptada = _adapt_clave_message(key, l)

    message_bytes = message.encode("latin-1")
    clave_adaptada_bytes = clave_adaptada.encode("latin-1")

    encrypted_bytes = []
    for i in range(l):
        ascii_mensaje = message_bytes[i]
        ascii_clave = clave_adaptada_bytes[i]

        mult_clave = ascii_clave * factor_clave
        mult_i3 = (i + 1) * 3

        suma_total = ascii_mensaje + mult_clave + mult_i3
        valor_final = suma_total % 256
        encrypted_bytes.append(valor_final)

    final_bytes = bytes(encrypted_bytes)
    return base64.b64encode(final_bytes).decode("ascii")


def custom_decrypt_message(encrypted_base64_string: str, key: str) -> str:
    """
    Descifra un mensaje Base64 cifrado utilizando la lógica personalizada de VBA.
    """
    try:
        decoded_bytes = base64.b64decode(encrypted_base64_string)
    except Exception as e:
        raise ValueError(f"Cadena Base64 inválida o corrupta para mensaje: {e}")

    l = len(decoded_bytes)
    factor_clave = _calculate_factor_clave_message(l)
    clave_adaptada = _adapt_clave_message(key, l)

    clave_adaptada_bytes = clave_adaptada.encode("latin-1")

    decrypted_bytes = []
    for i in range(l):
        ascii_cifrado = decoded_bytes[i]
        ascii_clave = clave_adaptada_bytes[i]

        mult_clave = ascii_clave * factor_clave
        mult_i3 = (i + 1) * 3

        valor_final = (ascii_cifrado - mult_clave - mult_i3) % 256
        decrypted_bytes.append(valor_final)

    return bytes(decrypted_bytes).decode("latin-1")


# User's NEW Key Encryption Logic (Python implementation of VBA functions)
# Estas funciones NO usan una clave externa para su propio cifrado/descifrado,
# la "clave" se deriva de la longitud del dato a cifrar/descifrar.
def cifrar_clave_custom(plain_key: str) -> str:
    """
    Cifra una clave de texto plano utilizando la lógica personalizada del usuario.
    La "clave" para este cifrado se deriva de la longitud de 'plain_key'.
    """
    l = len(plain_key)
    if l == 0:
        raise ValueError("La clave a cifrar no puede estar vacía.")

    suma_pos = sum(range(1, l + 1))
    suma_digitos = sum(int(d) for d in str(l))
    factor = l + suma_digitos + suma_pos

    plain_key_bytes = plain_key.encode(
        "latin-1"
    )  # Usar latin-1 para operaciones byte a byte

    encrypted_bytes = bytearray()
    for i in range(1, l + 1):
        char_ascii = plain_key_bytes[
            i - 1
        ]  # Python es 0-indexado para acceso a strings

        valor = (char_ascii + i * 3 + factor) % 256
        encrypted_bytes.append(valor)

    return base64.b64encode(encrypted_bytes).decode("ascii")


def descifrar_clave_custom(encrypted_base64_key: str) -> str:
    """
    Descifra una clave cifrada en Base64 utilizando la lógica personalizada del usuario.
    La "clave" para este descifrado se deriva de la longitud del contenido cifrado.
    """
    try:
        bytes_data = base64.b64decode(encrypted_base64_key)
    except Exception as e:
        raise ValueError(f"Cadena Base64 inválida o corrupta para clave: {e}")

    l = len(bytes_data)
    if l == 0:
        raise ValueError("La clave cifrada no puede estar vacía para descifrar.")

    suma_pos = sum(range(1, l + 1))
    suma_digitos = sum(int(d) for d in str(l))
    factor = l + suma_digitos + suma_pos

    decrypted_bytes = []
    for i in range(1, l + 1):
        ascii_cifrado = bytes_data[i - 1]  # Python es 0-indexado

        valor = (ascii_cifrado - i * 3 - factor) % 256
        decrypted_bytes.append(valor)

    return bytes(decrypted_bytes).decode("latin-1")
