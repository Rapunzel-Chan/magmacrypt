"""
ГОСТ Р 34.13-2015. Режимы работы блочных шифров.
Реализация для шифра Магма (длина блока 64 бита = 8 байт).

Режимы:
1. ECB - Electronic Codebook (простая замена)
2. CBC - Cipher Block Chaining (простая замена с зацеплением)
3. CFB - Cipher Feedback (гаммирование с обратной связью по шифртексту)
4. OFB - Output Feedback (гаммирование с обратной связью по выходу)
5. CTR - Counter (гаммирование)
6. MAC - Message Authentication Code (выработка имитовставки)
"""

import os
from typing import Optional, Tuple
from magma_code import MagmaCipher


# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Побитовое XOR двух байтовых строк одинаковой длины."""
    return bytes(x ^ y for x, y in zip(a, b))


def _msb(data: bytes, bits: int) -> bytes:
    """
    Взятие старших битов (MSB) из байтовой строки.
    bits - количество бит (должно быть кратно 8 для корректной работы)
    """
    bytes_needed = (bits + 7) // 8
    return data[:bytes_needed]


def _lsb(data: bytes, bits: int) -> bytes:
    """
    Взятие младших битов (LSB) из байтовой строки.
    bits - количество бит (должно быть кратно 8 для корректной работы)
    """
    bytes_needed = (bits + 7) // 8
    return data[-bytes_needed:]


def _int_to_bytes(value: int, length: int) -> bytes:
    """Преобразует целое число в байтовую строку фиксированной длины (big-endian)."""
    return value.to_bytes(length, byteorder='big')


def _bytes_to_int(data: bytes) -> int:
    """Преобразует байтовую строку в целое число (big-endian)."""
    return int.from_bytes(data, byteorder='big')


# ============================================================================
# РЕЖИМ 1: ECB (Electronic Codebook) - простая замена
# ============================================================================

class ModeECB:
    """
    Режим простой замены (Electronic Codebook).
    Каждый блок шифруется независимо.
    Требуется паддинг PKCS#7.
    """

    def __init__(self, cipher: MagmaCipher):
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE

    @staticmethod
    def _add_padding(data: bytes) -> bytes:
        """PKCS#7 паддинг до размера блока."""
        padding_len = MagmaCipher.BLOCK_SIZE - (len(data) % MagmaCipher.BLOCK_SIZE)
        if padding_len == 0:
            padding_len = MagmaCipher.BLOCK_SIZE
        return data + bytes([padding_len] * padding_len)

    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """Удаление PKCS#7 паддинга."""
        if not data:
            return data
        padding_len = data[-1]
        if padding_len > MagmaCipher.BLOCK_SIZE or padding_len == 0:
            raise ValueError("Неверный паддинг")
        if data[-padding_len:] != bytes([padding_len]) * padding_len:
            raise ValueError("Неверный паддинг")
        return data[:-padding_len]

    def encrypt(self, data: bytes) -> bytes:
        """Зашифрование."""
        padded = self._add_padding(data)
        result = bytearray()
        for i in range(0, len(padded), self._block_size):
            block = padded[i:i + self._block_size]
            result.extend(self._cipher.encrypt_block(block))
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование."""
        if len(data) % self._block_size != 0:
            raise ValueError("Данные должны быть кратны размеру блока")
        result = bytearray()
        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            result.extend(self._cipher.decrypt_block(block))
        return self._remove_padding(bytes(result))


# ============================================================================
# РЕЖИМ 2: CBC (Cipher Block Chaining) - простая замена с зацеплением
# ============================================================================

class ModeCBC:
    """
    Режим простой замены с зацеплением (Cipher Block Chaining).
    Каждый блок шифруется с зависимостью от предыдущего шифротекста.
    Требуется IV (вектор инициализации) и паддинг.
    IV должен быть 8 байт (64 бита).
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes):
        if len(iv) != MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"IV должен быть {MagmaCipher.BLOCK_SIZE} байт, получено {len(iv)}")
        self._cipher = cipher
        self._iv = iv
        self._block_size = MagmaCipher.BLOCK_SIZE

    @staticmethod
    def _add_padding(data: bytes) -> bytes:
        padding_len = MagmaCipher.BLOCK_SIZE - (len(data) % MagmaCipher.BLOCK_SIZE)
        if padding_len == 0:
            padding_len = MagmaCipher.BLOCK_SIZE
        return data + bytes([padding_len] * padding_len)

    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        if not data:
            return data
        padding_len = data[-1]
        if padding_len > MagmaCipher.BLOCK_SIZE or padding_len == 0:
            raise ValueError("Неверный паддинг")
        if data[-padding_len:] != bytes([padding_len]) * padding_len:
            raise ValueError("Неверный паддинг")
        return data[:-padding_len]

    def encrypt(self, data: bytes) -> bytes:
        """
        Зашифрование в режиме CBC.
        C_i = E_K(P_i ⊕ C_{i-1}), где C_0 = IV
        """
        padded = self._add_padding(data)
        result = bytearray()
        prev = self._iv

        for i in range(0, len(padded), self._block_size):
            block = padded[i:i + self._block_size]
            xored = _xor_bytes(block, prev)
            encrypted = self._cipher.encrypt_block(xored)
            result.extend(encrypted)
            prev = encrypted

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        Расшифрование в режиме CBC.
        P_i = D_K(C_i) ⊕ C_{i-1}, где C_0 = IV
        """
        if len(data) % self._block_size != 0:
            raise ValueError("Данные должны быть кратны размеру блока")
        result = bytearray()
        prev = self._iv

        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            decrypted = self._cipher.decrypt_block(block)
            xored = _xor_bytes(decrypted, prev)
            result.extend(xored)
            prev = block

        return self._remove_padding(bytes(result))


# ============================================================================
# РЕЖИМ 3: CFB (Cipher Feedback) - гаммирование с обратной связью по шифртексту
# ============================================================================

class ModeCFB:
    """
    Режим гаммирования с обратной связью по шифртексту (Cipher Feedback).
    Гамма вырабатывается из предыдущего шифротекста.
    Не требует паддинга.
    IV должен быть 8 байт (64 бита).
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes):
        if len(iv) != MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"IV должен быть {MagmaCipher.BLOCK_SIZE} байт, получено {len(iv)}")
        self._cipher = cipher
        self._iv = iv
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._s = MagmaCipher.BLOCK_SIZE * 8  # полный блок (64 бита)

    def _generate_gamma(self, feedback: bytes) -> bytes:
        """Выработка гаммы: зашифрование регистра сдвига."""
        return self._cipher.encrypt_block(feedback)

    def encrypt(self, data: bytes) -> bytes:
        """
        Зашифрование в режиме CFB.
        C_i = P_i ⊕ MSB_s(E_K(R_i))
        R_{i+1} = LSB_{m-s}(R_i) || C_i
        """
        result = bytearray()
        feedback = self._iv
        s_bytes = self._s // 8  # 8 байт

        for i in range(0, len(data), s_bytes):
            block = data[i:i + s_bytes]
            gamma = self._generate_gamma(feedback)
            gamma_trunc = _msb(gamma, self._s)
            encrypted = _xor_bytes(block, gamma_trunc[:len(block)])
            result.extend(encrypted)
            # Сдвиг регистра
            feedback = feedback[len(encrypted):] + encrypted

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        Расшифрование в режиме CFB (то же, что шифрование).
        """
        result = bytearray()
        feedback = self._iv
        s_bytes = self._s // 8

        for i in range(0, len(data), s_bytes):
            block = data[i:i + s_bytes]
            gamma = self._generate_gamma(feedback)
            gamma_trunc = _msb(gamma, self._s)
            decrypted = _xor_bytes(block, gamma_trunc[:len(block)])
            result.extend(decrypted)
            feedback = feedback[len(block):] + block

        return bytes(result)


# ============================================================================
# РЕЖИМ 4: OFB (Output Feedback) - гаммирование с обратной связью по выходу
# ============================================================================

class ModeOFB:
    """
    Режим гаммирования с обратной связью по выходу (Output Feedback).
    Гамма вырабатывается из предыдущего выхода шифра.
    Не требует паддинга.
    IV должен быть 8 байт (64 бита).
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes):
        if len(iv) != MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"IV должен быть {MagmaCipher.BLOCK_SIZE} байт, получено {len(iv)}")
        self._cipher = cipher
        self._iv = iv
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._s = MagmaCipher.BLOCK_SIZE * 8

    def _generate_gamma(self, feedback: bytes) -> bytes:
        """Выработка гаммы: зашифрование регистра сдвига."""
        return self._cipher.encrypt_block(feedback)

    def encrypt(self, data: bytes) -> bytes:
        """
        Зашифрование в режиме OFB.
        Y_i = E_K(R_i)
        C_i = P_i ⊕ MSB_s(Y_i)
        R_{i+1} = LSB_{m-s}(R_i) || Y_i
        """
        result = bytearray()
        feedback = self._iv
        s_bytes = self._s // 8

        for i in range(0, len(data), s_bytes):
            block = data[i:i + s_bytes]
            gamma = self._generate_gamma(feedback)
            gamma_trunc = _msb(gamma, self._s)
            encrypted = _xor_bytes(block, gamma_trunc[:len(block)])
            result.extend(encrypted)
            feedback = feedback[len(block):] + gamma

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование в режиме OFB (то же, что шифрование)."""
        return self.encrypt(data)


# ============================================================================
# РЕЖИМ 5: CTR (Counter) - гаммирование
# ============================================================================

class ModeCTR:
    """
    Режим гаммирования (Counter).
    Гамма вырабатывается путем зашифрования счетчика.
    Не требует паддинга.
    nonce: уникальное значение (обычно 4-8 байт)
    """

    def __init__(self, cipher: MagmaCipher, nonce: bytes, counter_start: int = 0):
        if len(nonce) > MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"nonce не может быть больше {MagmaCipher.BLOCK_SIZE} байт")
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._nonce = nonce
        self._counter = counter_start

    def _get_counter_block(self) -> bytes:
        """Формирует блок счетчика: nonce || counter (занимает весь блок)."""
        counter_bytes = _int_to_bytes(self._counter, self._block_size - len(self._nonce))
        return self._nonce + counter_bytes

    def _increment_counter(self):
        self._counter += 1

    def _process(self, data: bytes) -> bytes:
        result = bytearray()
        self._counter = 0

        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            counter_block = self._get_counter_block()
            gamma = self._cipher.encrypt_block(counter_block)
            xored = _xor_bytes(block, gamma[:len(block)])
            result.extend(xored)
            self._increment_counter()

        return bytes(result)

    def encrypt(self, data: bytes) -> bytes:
        return self._process(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._process(data)


# ============================================================================
# РЕЖИМ 6: MAC (Message Authentication Code) - выработка имитовставки
# ============================================================================

class ModeMAC:
    """
    Режим выработки имитовставки (Message Authentication Code).
    Вырабатывает контрольную комбинацию для проверки целостности.
    """

    def __init__(self, cipher: MagmaCipher):
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE

    def _compute_mac(self, data: bytes, key1: bytes, key2: bytes, s: int) -> bytes:
        """
        Вычисление MAC по ГОСТ Р 34.13-2015.
        Обрабатывает пустые данные и граничные случаи.
        """
        # Обработка пустых данных
        if not data:
            # Для пустых данных: один блок из нулей
            blocks = [bytes(self._block_size)]
            full_last_block = True
        else:
            blocks = [data[i:i + self._block_size] for i in range(0, len(data), self._block_size)]
            last_block_len = len(blocks[-1])
            full_last_block = (last_block_len == self._block_size)

        # Дополнение последнего блока
        if full_last_block:
            k_star = key1
            padded_last = blocks[-1]
        else:
            k_star = key2
            # Процедура 3: P_q^* = P_q || 1 || 0^{n-r-1}
            padded_last = blocks[-1] + b'\x80' + b'\x00' * (self._block_size - len(blocks[-1]) - 1)
            blocks = blocks[:-1] + [padded_last]

        # Инициализация
        c_prev = bytes(self._block_size)  # C_0 = 0^n

        # Обработка всех блоков кроме последнего
        for block in blocks[:-1]:
            xored = _xor_bytes(block, c_prev)
            c_prev = self._cipher.encrypt_block(xored)

        # Обработка последнего блока с K*
        last_xored = _xor_bytes(blocks[-1], c_prev)
        last_xored = _xor_bytes(last_xored, k_star)
        last_encrypted = self._cipher.encrypt_block(last_xored)

        # Усечение до s бит
        s_bytes = (s + 7) // 8
        return last_encrypted[:s_bytes]

    def _derive_keys(self) -> Tuple[bytes, bytes]:
        """
        Выработка ключей K1 и K2 для MAC по ГОСТ.
        """
        zero_block = bytes(self._block_size)
        r = self._cipher.encrypt_block(zero_block)

        if self._block_size == 8:
            b_n = (0x1B).to_bytes(8, 'big')
        else:
            raise ValueError(f"Поддерживается только блок 64 бита")

        def left_shift_one(data: bytes) -> bytes:
            value = int.from_bytes(data, 'big')
            shifted = (value << 1) & ((1 << (self._block_size * 8)) - 1)
            return shifted.to_bytes(self._block_size, 'big')

        def msb_one(data: bytes) -> int:
            return (data[0] >> 7) & 1

        # K1
        shifted = left_shift_one(r)
        if msb_one(r) == 0:
            k1 = shifted
        else:
            k1 = _xor_bytes(shifted, b_n)

        # K2
        shifted = left_shift_one(k1)
        if msb_one(k1) == 0:
            k2 = shifted
        else:
            k2 = _xor_bytes(shifted, b_n)

        return k1, k2

    def generate(self, data: bytes, s: int = 32) -> bytes:
        """
        Выработка имитовставки (MAC) для данных.
        s - длина имитовставки в битах (по умолчанию 32 бита).
        """
        if s <= 0 or s > self._block_size * 8:
            raise ValueError(f"s должно быть от 1 до {self._block_size * 8}")
        k1, k2 = self._derive_keys()
        return self._compute_mac(data, k1, k2, s)

    def verify(self, data: bytes, mac: bytes, s: int = 32) -> bool:
        """
        Проверка имитовставки.
        """
        expected_mac = self.generate(data, s)
        return expected_mac == mac


# ============================================================================
# ТЕСТИРОВАНИЕ ВСЕХ РЕЖИМОВ
# ============================================================================

def test_modes():
    """Тестирование всех 6 режимов работы."""
    print("=" * 70)
    print("ТЕСТИРОВАНИЕ РЕЖИМОВ РАБОТЫ (ГОСТ Р 34.13-2015)")
    print("=" * 70)

    # Ключ из ГОСТ
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    key = bytes.fromhex(key_hex)
    cipher = MagmaCipher(key)

    # Тестовые данные
    test_data = b"Hello, World! This is a test message for Magma cipher."
    print(f"\nИсходные данные ({len(test_data)} байт): {test_data}")

    # 1. ECB
    print("\n" + "-" * 50)
    print("1. ECB (Electronic Codebook) - простая замена")
    ecb = ModeECB(cipher)
    encrypted_ecb = ecb.encrypt(test_data)
    decrypted_ecb = ecb.decrypt(encrypted_ecb)
    print(f"   Зашифровано: {len(encrypted_ecb)} байт")
    print(f"   Расшифровано: {decrypted_ecb}")
    print(f"   ✓ УСПЕШНО" if decrypted_ecb == test_data else "   ✗ ОШИБКА")

    # 2. CBC
    print("\n" + "-" * 50)
    print("2. CBC (Cipher Block Chaining) - простая замена с зацеплением")
    iv = bytes.fromhex("1234567890abcdef")
    cbc = ModeCBC(cipher, iv)
    encrypted_cbc = cbc.encrypt(test_data)
    decrypted_cbc = cbc.decrypt(encrypted_cbc)
    print(f"   IV: {iv.hex()}")
    print(f"   Зашифровано: {len(encrypted_cbc)} байт")
    print(f"   Расшифровано: {decrypted_cbc}")
    print(f"   ✓ УСПЕШНО" if decrypted_cbc == test_data else "   ✗ ОШИБКА")

    # 3. CFB
    print("\n" + "-" * 50)
    print("3. CFB (Cipher Feedback) - гаммирование с обратной связью по шифртексту")
    iv = bytes.fromhex("1234567890abcdef")
    cfb = ModeCFB(cipher, iv)
    encrypted_cfb = cfb.encrypt(test_data)
    decrypted_cfb = cfb.decrypt(encrypted_cfb)
    print(f"   IV: {iv.hex()}")
    print(f"   Зашифровано: {len(encrypted_cfb)} байт")
    print(f"   Расшифровано: {decrypted_cfb}")
    print(f"   ✓ УСПЕШНО" if decrypted_cfb == test_data else "   ✗ ОШИБКА")

    # 4. OFB
    print("\n" + "-" * 50)
    print("4. OFB (Output Feedback) - гаммирование с обратной связью по выходу")
    iv = bytes.fromhex("1234567890abcdef")
    ofb = ModeOFB(cipher, iv)
    encrypted_ofb = ofb.encrypt(test_data)
    decrypted_ofb = ofb.decrypt(encrypted_ofb)
    print(f"   IV: {iv.hex()}")
    print(f"   Зашифровано: {len(encrypted_ofb)} байт")
    print(f"   Расшифровано: {decrypted_ofb}")
    print(f"   ✓ УСПЕШНО" if decrypted_ofb == test_data else "   ✗ ОШИБКА")

    # 5. CTR
    print("\n" + "-" * 50)
    print("5. CTR (Counter) - гаммирование")
    nonce = bytes.fromhex("12345678")
    ctr = ModeCTR(cipher, nonce)
    encrypted_ctr = ctr.encrypt(test_data)
    ctr2 = ModeCTR(cipher, nonce)
    decrypted_ctr = ctr2.decrypt(encrypted_ctr)
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Зашифровано: {len(encrypted_ctr)} байт")
    print(f"   Расшифровано: {decrypted_ctr}")
    print(f"   ✓ УСПЕШНО" if decrypted_ctr == test_data else "   ✗ ОШИБКА")

    # 6. MAC
    print("\n" + "-" * 50)
    print("6. MAC (Message Authentication Code) - выработка имитовставки")
    mac = ModeMAC(cipher)
    mac_value = mac.generate(test_data, s=32)
    print(f"   MAC (32 бита): {mac_value.hex()}")
    is_valid = mac.verify(test_data, mac_value, s=32)
    print(f"   Проверка MAC: {'✓ ПРОЙДЕНА' if is_valid else '✗ НЕ ПРОЙДЕНА'}")

    corrupted_data = test_data[:-1] + b'X'
    is_valid_corrupted = mac.verify(corrupted_data, mac_value, s=32)
    print(f"   Проверка с измененными данными: {'✓ НЕ ПРОЙДЕНА' if not is_valid_corrupted else '✗ ПРОЙДЕНА (ошибка!)'}")

    print("\n" + "=" * 70)
    print("ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ")
    print("=" * 70)


# ============================================================================
# ТЕСТ MAC С КОНКРЕТНЫМИ ДАННЫМИ
# ============================================================================

def test_mac_with_known_data():
    """
    Тест MAC с конкретными тестовыми данными.
    Здесь нет контрольных примеров из ГОСТ, но можно проверить свойства.
    """
    print("\n" + "=" * 70)
    print("ТЕСТ MAC (имитовставка) - проверка свойств")
    print("=" * 70)

    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    cipher = MagmaCipher(key)
    mac = ModeMAC(cipher)

    # Тестовые данные (включая пустую строку)
    test_cases = [
        (b"", "пустые данные"),
        (b"A", "один байт"),
        (b"Hello", "5 байт"),
        (b"Hello, World!", "13 байт (неполный блок)"),
        (b"ABCDEFGH", "ровно один блок (8 байт)"),
        (b"ABCDEFGHABCDEFGH", "ровно два блока (16 байт)"),
    ]

    print("\nГенерация MAC для разных данных (s=32 бита):")
    print("-" * 50)

    for data, desc in test_cases:
        mac_value = mac.generate(data, s=32)
        print(f"  {desc:30} -> {mac_value.hex()}")

    print("\n" + "-" * 50)
    print("Проверка верификации:")
    print("-" * 50)

    data = b"Hello, World!"
    mac_value = mac.generate(data, s=32)
    print(f"  Данные: {data}")
    print(f"  MAC: {mac_value.hex()}")
    print(f"  Верификация (правильные данные): {mac.verify(data, mac_value, s=32)}")
    print(f"  Верификация (измененные данные): {mac.verify(b'Hello, World!X', mac_value, s=32)}")
    print(f"  Верификация (пустые данные): {mac.verify(b'', mac_value, s=32)}")

    print("\n" + "-" * 50)
    print("Разные длины MAC (s):")
    print("-" * 50)

    data = b"Test message for MAC"
    for s in [16, 24, 32, 40, 48, 56, 64]:
        mac_value = mac.generate(data, s=s)
        print(f"  s={s:2d} бит -> {mac_value.hex()} (длина: {len(mac_value)} байт)")


# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    test_modes()
    test_mac_with_known_data()