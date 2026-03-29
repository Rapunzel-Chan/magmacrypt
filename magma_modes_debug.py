"""
Отладочная версия режимов работы по ГОСТ Р 34.13-2015.
С пошаговым выводом для проверки работы каждого режима.
"""

import os
import sys
from typing import Optional, Tuple

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from magma_code import MagmaCipher, MagmaSBoxes, MagmaKeySchedule, MagmaFeistelFunction
from magma_modes import _xor_bytes, _msb, _lsb, _int_to_bytes, _bytes_to_int


# ============================================================================
# ДЕБАГ-ВЕРСИЯ РЕЖИМОВ
# ============================================================================

class ModeECBDebug:
    """Отладочная версия ECB с пошаговым выводом."""

    def __init__(self, cipher: MagmaCipher, debug: bool = False):
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self.debug = debug

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
        """Зашифрование с отладочным выводом."""
        padded = self._add_padding(data)
        if self.debug:
            print(f"\n  ECB: исходные данные ({len(data)} байт)")
            print(f"  ECB: после паддинга ({len(padded)} байт): {padded.hex()}")
            print(f"  ECB: разбивка на блоки по {self._block_size} байт:")

        result = bytearray()
        for i in range(0, len(padded), self._block_size):
            block = padded[i:i + self._block_size]
            if self.debug:
                print(f"\n    Блок {i//self._block_size + 1}: {block.hex()}")

            encrypted = self._cipher.encrypt_block(block)
            if self.debug:
                print(f"    Зашифровано: {encrypted.hex()}")

            result.extend(encrypted)

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование с отладочным выводом."""
        if self.debug:
            print(f"\n  ECB: шифротекст ({len(data)} байт)")
            print(f"  ECB: разбивка на блоки по {self._block_size} байт:")

        result = bytearray()
        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            if self.debug:
                print(f"\n    Блок {i//self._block_size + 1}: {block.hex()}")

            decrypted = self._cipher.decrypt_block(block)
            if self.debug:
                print(f"    Расшифровано: {decrypted.hex()}")

            result.extend(decrypted)

        if self.debug:
            print(f"\n  ECB: после расшифрования: {bytes(result).hex()}")

        return self._remove_padding(bytes(result))


class ModeCBCDebug:
    """Отладочная версия CBC с пошаговым выводом."""

    def __init__(self, cipher: MagmaCipher, iv: bytes, debug: bool = False):
        if len(iv) != MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"IV должен быть {MagmaCipher.BLOCK_SIZE} байт")
        self._cipher = cipher
        self._iv = iv
        self._block_size = MagmaCipher.BLOCK_SIZE
        self.debug = debug

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
        """Зашифрование в режиме CBC с отладочным выводом."""
        padded = self._add_padding(data)

        if self.debug:
            print(f"\n  CBC: исходные данные ({len(data)} байт)")
            print(f"  CBC: после паддинга ({len(padded)} байт): {padded.hex()}")
            print(f"  CBC: IV = {self._iv.hex()}")
            print(f"  CBC: разбивка на блоки по {self._block_size} байт:")

        result = bytearray()
        prev = self._iv

        for i in range(0, len(padded), self._block_size):
            block = padded[i:i + self._block_size]
            if self.debug:
                print(f"\n    Блок {i//self._block_size + 1}:")
                print(f"      P_i = {block.hex()}")
                print(f"      C_{i-1} = {prev.hex()}")
                print(f"      P_i ⊕ C_{i-1} = {_xor_bytes(block, prev).hex()}")

            xored = _xor_bytes(block, prev)
            encrypted = self._cipher.encrypt_block(xored)

            if self.debug:
                print(f"      E_K(...) = {encrypted.hex()}")
                print(f"      C_i = {encrypted.hex()}")

            result.extend(encrypted)
            prev = encrypted

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование в режиме CBC с отладочным выводом."""
        if self.debug:
            print(f"\n  CBC: шифротекст ({len(data)} байт)")
            print(f"  CBC: IV = {self._iv.hex()}")

        result = bytearray()
        prev = self._iv

        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            if self.debug:
                print(f"\n    Блок {i//self._block_size + 1}:")
                print(f"      C_i = {block.hex()}")
                print(f"      C_{i-1} = {prev.hex()}")

            decrypted = self._cipher.decrypt_block(block)

            if self.debug:
                print(f"      D_K(C_i) = {decrypted.hex()}")

            xored = _xor_bytes(decrypted, prev)

            if self.debug:
                print(f"      D_K(C_i) ⊕ C_{i-1} = {xored.hex()}")

            result.extend(xored)
            prev = block

        if self.debug:
            print(f"\n  CBC: после расшифрования: {bytes(result).hex()}")

        return self._remove_padding(bytes(result))


class ModeCFBDebug:
    """Отладочная версия CFB с пошаговым выводом."""

    def __init__(self, cipher: MagmaCipher, iv: bytes, debug: bool = False):
        if len(iv) != MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"IV должен быть {MagmaCipher.BLOCK_SIZE} байт")
        self._cipher = cipher
        self._iv = iv
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._s = MagmaCipher.BLOCK_SIZE * 8  # 64 бита
        self.debug = debug

    def _generate_gamma(self, feedback: bytes) -> bytes:
        """Выработка гаммы."""
        encrypted = self._cipher.encrypt_block(feedback)
        return encrypted

    def encrypt(self, data: bytes) -> bytes:
        """Зашифрование в режиме CFB с отладочным выводом."""
        if self.debug:
            print(f"\n  CFB: исходные данные ({len(data)} байт): {data.hex()}")
            print(f"  CFB: IV = {self._iv.hex()}")
            print(f"  CFB: s = {self._s} бит (полный блок)")

        result = bytearray()
        feedback = self._iv
        s_bytes = self._s // 8

        for i in range(0, len(data), s_bytes):
            block = data[i:i + s_bytes]

            if self.debug:
                print(f"\n    Шаг {i//s_bytes + 1}:")
                print(f"      Регистр сдвига = {feedback.hex()}")
                print(f"      Блок данных = {block.hex()}")

            gamma = self._generate_gamma(feedback)

            if self.debug:
                print(f"      E_K(регистр) = {gamma.hex()}")
                gamma_trunc = _msb(gamma, self._s)
                print(f"      Гамма (MSB_{self._s}) = {gamma_trunc.hex()}")

            gamma_trunc = _msb(gamma, self._s)
            encrypted = _xor_bytes(block, gamma_trunc[:len(block)])

            if self.debug:
                print(f"      C_i = P_i ⊕ гамма = {encrypted.hex()}")

            result.extend(encrypted)

            # Сдвиг регистра
            feedback = feedback[len(encrypted):] + encrypted
            if self.debug:
                print(f"      Новый регистр = {feedback.hex()}")

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование в режиме CFB с отладочным выводом."""
        if self.debug:
            print(f"\n  CFB: шифротекст ({len(data)} байт): {data.hex()}")
            print(f"  CFB: IV = {self._iv.hex()}")

        result = bytearray()
        feedback = self._iv
        s_bytes = self._s // 8

        for i in range(0, len(data), s_bytes):
            block = data[i:i + s_bytes]

            if self.debug:
                print(f"\n    Шаг {i//s_bytes + 1}:")
                print(f"      Регистр сдвига = {feedback.hex()}")
                print(f"      Блок шифротекста = {block.hex()}")

            gamma = self._generate_gamma(feedback)

            if self.debug:
                print(f"      E_K(регистр) = {gamma.hex()}")
                gamma_trunc = _msb(gamma, self._s)
                print(f"      Гамма (MSB_{self._s}) = {gamma_trunc.hex()}")

            gamma_trunc = _msb(gamma, self._s)
            decrypted = _xor_bytes(block, gamma_trunc[:len(block)])

            if self.debug:
                print(f"      P_i = C_i ⊕ гамма = {decrypted.hex()}")

            result.extend(decrypted)
            feedback = feedback[len(block):] + block

            if self.debug:
                print(f"      Новый регистр = {feedback.hex()}")

        return bytes(result)


class ModeOFBDebug:
    """Отладочная версия OFB с пошаговым выводом."""

    def __init__(self, cipher: MagmaCipher, iv: bytes, debug: bool = False):
        if len(iv) != MagmaCipher.BLOCK_SIZE:
            raise ValueError(f"IV должен быть {MagmaCipher.BLOCK_SIZE} байт")
        self._cipher = cipher
        self._iv = iv
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._s = MagmaCipher.BLOCK_SIZE * 8
        self.debug = debug

    def encrypt(self, data: bytes) -> bytes:
        """Зашифрование в режиме OFB с отладочным выводом."""
        if self.debug:
            print(f"\n  OFB: исходные данные ({len(data)} байт): {data.hex()}")
            print(f"  OFB: IV = {self._iv.hex()}")

        result = bytearray()
        feedback = self._iv
        s_bytes = self._s // 8

        for i in range(0, len(data), s_bytes):
            block = data[i:i + s_bytes]

            if self.debug:
                print(f"\n    Шаг {i//s_bytes + 1}:")
                print(f"      R_i = {feedback.hex()}")
                print(f"      Блок данных = {block.hex()}")

            gamma = self._cipher.encrypt_block(feedback)

            if self.debug:
                print(f"      Y_i = E_K(R_i) = {gamma.hex()}")
                gamma_trunc = _msb(gamma, self._s)
                print(f"      Гамма = {gamma_trunc.hex()}")

            gamma_trunc = _msb(gamma, self._s)
            encrypted = _xor_bytes(block, gamma_trunc[:len(block)])

            if self.debug:
                print(f"      C_i = P_i ⊕ гамма = {encrypted.hex()}")

            result.extend(encrypted)
            feedback = gamma

            if self.debug:
                print(f"      R_{i+1} = Y_i = {feedback.hex()}")

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование в режиме OFB (то же, что шифрование)."""
        return self.encrypt(data)


class ModeCTRDebug:
    """Отладочная версия CTR с пошаговым выводом."""

    def __init__(self, cipher: MagmaCipher, nonce: bytes, debug: bool = False):
        self._cipher = cipher
        self._nonce = nonce
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._counter = 0
        self.debug = debug

    def _get_counter_block(self) -> bytes:
        """Формирует блок счетчика."""
        counter_bytes = _int_to_bytes(self._counter, self._block_size - len(self._nonce))
        return self._nonce + counter_bytes

    def _increment_counter(self):
        self._counter += 1

    def _process(self, data: bytes, mode_name: str) -> bytes:
        """Общая логика с отладочным выводом."""
        if self.debug:
            print(f"\n  {mode_name}: исходные данные ({len(data)} байт): {data.hex()}")
            print(f"  {mode_name}: nonce = {self._nonce.hex()}")

        result = bytearray()
        self._counter = 0

        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            counter_block = self._get_counter_block()

            if self.debug:
                print(f"\n    Блок {i//self._block_size + 1}:")
                print(f"      Счетчик = {counter_block.hex()} (counter = {self._counter})")
                print(f"      Блок данных = {block.hex()}")

            gamma = self._cipher.encrypt_block(counter_block)

            if self.debug:
                print(f"      Гамма = E_K(счетчик) = {gamma.hex()}")

            xored = _xor_bytes(block, gamma[:len(block)])

            if self.debug:
                print(f"      Результат = блок ⊕ гамма = {xored.hex()}")

            result.extend(xored)
            self._increment_counter()

        return bytes(result)

    def encrypt(self, data: bytes) -> bytes:
        return self._process(data, "CTR")

    def decrypt(self, data: bytes) -> bytes:
        return self._process(data, "CTR")


class ModeMACDebug:
    """Отладочная версия MAC с пошаговым выводом."""

    def __init__(self, cipher: MagmaCipher, debug: bool = False):
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self.debug = debug

    def _derive_keys(self) -> Tuple[bytes, bytes]:
        """Выработка ключей K1 и K2."""
        zero_block = bytes(self._block_size)
        r = self._cipher.encrypt_block(zero_block)

        if self.debug:
            print(f"\n  MAC: R = E_K(0^n) = {r.hex()}")

        # Константа B_n для n=64
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

        if self.debug:
            print(f"  MAC: K1 = {k1.hex()}")

        # K2
        shifted = left_shift_one(k1)
        if msb_one(k1) == 0:
            k2 = shifted
        else:
            k2 = _xor_bytes(shifted, b_n)

        if self.debug:
            print(f"  MAC: K2 = {k2.hex()}")

        return k1, k2

    def _compute_mac(self, data: bytes, k1: bytes, k2: bytes, s: int) -> bytes:
        """Вычисление MAC с отладочным выводом."""
        if not data:
            blocks = [bytes(self._block_size)]
            full_last_block = True
        else:
            blocks = [data[i:i + self._block_size] for i in range(0, len(data), self._block_size)]
            last_block_len = len(blocks[-1])
            full_last_block = (last_block_len == self._block_size)

        if self.debug:
            print(f"\n  MAC: количество блоков: {len(blocks)}")
            print(f"  MAC: последний блок полный: {full_last_block}")

        if full_last_block:
            k_star = k1
            padded_last = blocks[-1]
            if self.debug:
                print(f"  MAC: K* = K1")
                print(f"  MAC: последний блок без изменений: {padded_last.hex()}")
        else:
            k_star = k2
            # Процедура 3: P_q^* = P_q || 1 || 0^{n-r-1}
            padded_last = blocks[-1] + b'\x80' + b'\x00' * (self._block_size - len(blocks[-1]) - 1)
            blocks = blocks[:-1] + [padded_last]
            if self.debug:
                print(f"  MAC: K* = K2")
                print(f"  MAC: последний блок с паддингом: {padded_last.hex()}")

        # Инициализация
        c_prev = bytes(self._block_size)
        if self.debug:
            print(f"\n  MAC: C_0 = {c_prev.hex()}")

        # Обработка всех блоков кроме последнего
        for idx, block in enumerate(blocks[:-1]):
            xored = _xor_bytes(block, c_prev)
            if self.debug:
                print(f"\n    Блок {idx + 1}:")
                print(f"      P_{idx + 1} = {block.hex()}")
                print(f"      C_{idx} = {c_prev.hex()}")
                print(f"      P_{idx + 1} ⊕ C_{idx} = {xored.hex()}")

            c_prev = self._cipher.encrypt_block(xored)

            if self.debug:
                print(f"      E_K(...) = {c_prev.hex()}")
                print(f"      C_{idx + 1} = {c_prev.hex()}")

        # Обработка последнего блока с K*
        last_block = blocks[-1]
        last_idx = len(blocks) - 1
        xored = _xor_bytes(last_block, c_prev)
        xored = _xor_bytes(xored, k_star)

        if self.debug:
            print(f"\n    Последний блок:")
            print(f"      P_{last_idx + 1}* = {last_block.hex()}")
            print(f"      C_{last_idx} = {c_prev.hex()}")
            print(f"      P_{last_idx + 1}* ⊕ C_{last_idx} = {_xor_bytes(last_block, c_prev).hex()}")
            print(f"      K* = {k_star.hex()}")
            print(f"      (P* ⊕ C_{last_idx}) ⊕ K* = {xored.hex()}")

        last_encrypted = self._cipher.encrypt_block(xored)

        if self.debug:
            print(f"      E_K(...) = {last_encrypted.hex()}")

        # Усечение до s бит
        s_bytes = (s + 7) // 8
        mac = last_encrypted[:s_bytes]

        if self.debug:
            print(f"      MAC (первые {s} бит) = {mac.hex()}")

        return mac

    def generate(self, data: bytes, s: int = 32) -> bytes:
        """Выработка MAC с отладочным выводом."""
        if self.debug:
            print(f"\n  MAC: генерация для данных ({len(data)} байт): {data.hex()}")
            print(f"  MAC: длина MAC: {s} бит")

        k1, k2 = self._derive_keys()
        return self._compute_mac(data, k1, k2, s)

    def verify(self, data: bytes, mac: bytes, s: int = 32) -> bool:
        """Проверка MAC с отладочным выводом."""
        if self.debug:
            print(f"\n  MAC: проверка MAC: {mac.hex()}")

        expected = self.generate(data, s)
        result = (expected == mac)

        if self.debug:
            print(f"  MAC: ожидалось: {expected.hex()}")
            print(f"  MAC: результат: {'✓ ПРОЙДЕНА' if result else '✗ НЕ ПРОЙДЕНА'}")

        return result


# ============================================================================
# ДЕБАГ-ТЕСТ ВСЕХ РЕЖИМОВ
# ============================================================================

def debug_all_modes():
    """Запуск всех режимов с отладочным выводом."""
    print("=" * 70)
    print("ОТЛАДОЧНЫЙ ТЕСТ ВСЕХ РЕЖИМОВ (ГОСТ Р 34.13-2015)")
    print("С пошаговым выводом промежуточных значений")
    print("=" * 70)

    # Ключ из ГОСТ
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    key = bytes.fromhex(key_hex)
    cipher = MagmaCipher(key)

    # Тестовые данные
    test_data = b"Hello, World! This is a test message."

    print(f"\nИсходные данные ({len(test_data)} байт): {test_data}")
    print(f"Ключ: {key.hex()}")

    # 1. ECB
    print("\n" + "=" * 70)
    print("1. ECB (Electronic Codebook) - простая замена")
    print("=" * 70)
    ecb = ModeECBDebug(cipher, debug=True)
    encrypted_ecb = ecb.encrypt(test_data)
    decrypted_ecb = ecb.decrypt(encrypted_ecb)
    print(f"\nРезультат: {'✓' if decrypted_ecb == test_data else '✗'}")

    # 2. CBC
    print("\n" + "=" * 70)
    print("2. CBC (Cipher Block Chaining) - простая замена с зацеплением")
    print("=" * 70)
    iv = bytes.fromhex("1234567890abcdef")
    cbc = ModeCBCDebug(cipher, iv, debug=True)
    encrypted_cbc = cbc.encrypt(test_data)
    decrypted_cbc = cbc.decrypt(encrypted_cbc)
    print(f"\nРезультат: {'✓' if decrypted_cbc == test_data else '✗'}")

    # 3. CFB
    print("\n" + "=" * 70)
    print("3. CFB (Cipher Feedback) - гаммирование с обратной связью по шифртексту")
    print("=" * 70)
    iv = bytes.fromhex("1234567890abcdef")
    cfb = ModeCFBDebug(cipher, iv, debug=True)
    encrypted_cfb = cfb.encrypt(test_data)
    decrypted_cfb = cfb.decrypt(encrypted_cfb)
    print(f"\nРезультат: {'✓' if decrypted_cfb == test_data else '✗'}")

    # 4. OFB
    print("\n" + "=" * 70)
    print("4. OFB (Output Feedback) - гаммирование с обратной связью по выходу")
    print("=" * 70)
    iv = bytes.fromhex("1234567890abcdef")
    ofb = ModeOFBDebug(cipher, iv, debug=True)
    encrypted_ofb = ofb.encrypt(test_data)
    decrypted_ofb = ofb.decrypt(encrypted_ofb)
    print(f"\nРезультат: {'✓' if decrypted_ofb == test_data else '✗'}")

    # 5. CTR
    print("\n" + "=" * 70)
    print("5. CTR (Counter) - гаммирование")
    print("=" * 70)
    nonce = bytes.fromhex("12345678")
    ctr = ModeCTRDebug(cipher, nonce, debug=True)
    encrypted_ctr = ctr.encrypt(test_data)
    ctr2 = ModeCTRDebug(cipher, nonce, debug=True)
    decrypted_ctr = ctr2.decrypt(encrypted_ctr)
    print(f"\nРезультат: {'✓' if decrypted_ctr == test_data else '✗'}")

    # 6. MAC
    print("\n" + "=" * 70)
    print("6. MAC (Message Authentication Code) - выработка имитовставки")
    print("=" * 70)
    mac = ModeMACDebug(cipher, debug=True)
    mac_value = mac.generate(test_data, s=32)
    print(f"\nMAC (32 бита): {mac_value.hex()}")
    is_valid = mac.verify(test_data, mac_value, s=32)
    print(f"Результат проверки: {'✓ ПРОЙДЕНА' if is_valid else '✗ НЕ ПРОЙДЕНА'}")

    print("\n" + "=" * 70)
    print("ОТЛАДОЧНЫЙ ТЕСТ ЗАВЕРШЕН")
    print("=" * 70)


# ============================================================================
# ДЕБАГ-ТЕСТ БАЗОВОГО ШИФРА (ПОРАУНДОВО)
# ============================================================================

def debug_magma_cipher():
    """Отладочный тест базового шифра с пошаговым выводом каждого раунда."""
    print("=" * 70)
    print("ОТЛАДОЧНЫЙ ТЕСТ БАЗОВОГО ШИФРА МАГМА")
    print("С пошаговым выводом каждого раунда")
    print("=" * 70)

    # Ключ из ГОСТ
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    key = bytes.fromhex(key_hex)

    # Открытый текст из ГОСТ
    plaintext_hex = "fedcba9876543210"
    plaintext = bytes.fromhex(plaintext_hex)

    # Ожидаемый шифротекст
    expected_hex = "4ee901e5c2d8ca3d"

    print(f"\nКлюч:           {key_hex}")
    print(f"Открытый текст: {plaintext_hex}")
    print(f"Ожидаемый шифр: {expected_hex}")

    # Создаем шифр
    cipher = MagmaCipher(key)

    # Получаем раундовые ключи
    round_keys = cipher._round_keys

    # Начальное состояние
    left = int.from_bytes(plaintext[:4], byteorder='big')
    right = int.from_bytes(plaintext[4:], byteorder='big')

    print(f"\nНачальное состояние:")
    print(f"  L0 = 0x{left:08X}, R0 = 0x{right:08X}")
    print("=" * 70)

    # 32 раунда с выводом
    for round_num in range(1, 33):
        round_key = round_keys[round_num - 1]

        print(f"\n--- РАУНД {round_num:2d} ---")
        print(f"  Вход: L = 0x{left:08X}, R = 0x{right:08X}")
        print(f"  Ключ K{round_num}: 0x{round_key:08X}")

        # Шаг a: сложение
        summed = (right + round_key) & 0xFFFFFFFF
        print(f"  Шаг 1: R + K = 0x{right:08X} + 0x{round_key:08X} = 0x{summed:08X}")

        # Шаг b: S-блоки (t-преобразование)
        transformed = MagmaFeistelFunction._t_transform(summed)
        print(f"  Шаг 2: После S-блоков (t) = 0x{transformed:08X}")

        # Шаг c: циклический сдвиг
        g_value = MagmaFeistelFunction._cyclic_left_shift_11(transformed)
        print(f"  Шаг 3: После сдвига на 11 (g) = 0x{g_value:08X}")

        # Шаг d: XOR
        new_right = left ^ g_value
        print(f"  Шаг 4: L XOR g = 0x{left:08X} XOR 0x{g_value:08X} = 0x{new_right:08X}")

        # Обновление
        new_left = right
        print(f"  Выход: L' = R = 0x{new_left:08X}, R' = 0x{new_right:08X}")

        left, right = new_left, new_right

    # Финальный результат (после 32 раундов меняем местами)
    result = right.to_bytes(4, 'big') + left.to_bytes(4, 'big')

    print("\n" + "=" * 70)
    print(f"РЕЗУЛЬТАТ ПОСЛЕ 32 РАУНДОВ:")
    print(f"  L = 0x{left:08X}, R = 0x{right:08X}")
    print(f"  Блок (R||L): {result.hex()}")
    print(f"  Ожидалось:   {expected_hex}")
    print("=" * 70)

    if result.hex() == expected_hex:
        print("\n✓ ВСЕ РАУНДЫ ПРОЙДЕНЫ УСПЕШНО!")
    else:
        print("\n✗ ОШИБКА! Результат не совпадает с ГОСТ.")


# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    # Отладка базового шифра (пораундово)
    debug_magma_cipher()

    # Отладка всех режимов
    debug_all_modes()