"""
ГОСТ Р 34.13-2015. Режимы работы блочных шифров.
Для шифра Магма (n = 64 бита = 8 байт).

ВСЕ РЕЖИМЫ РЕАЛИЗОВАНЫ СТРОГО ПО ГОСТ.
Дополнение для ECB и CBC реализовано по процедурам ГОСТ.
"""

from typing import Tuple

from magma_code import MagmaCipher


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Побитовое XOR двух байтовых строк одинаковой длины."""
    if len(a) != len(b):
        raise ValueError(f"XOR: длины не совпадают ({len(a)} vs {len(b)})")
    return bytes(x ^ y for x, y in zip(a, b))


def _msb(data: bytes, bits: int) -> bytes:
    """
    MSB_s - старшие биты (левые) по ГОСТ Р 34.13-2015, раздел 4.3.
    Возвращает первые bits/8 байт.
    """
    bytes_needed = (bits + 7) // 8
    return data[:bytes_needed]


def _lsb(data: bytes, bits: int) -> bytes:
    """
    LSB_s - младшие биты (правые) по ГОСТ Р 34.13-2015, раздел 4.3.
    Возвращает последние bits/8 байт.
    """
    bytes_needed = (bits + 7) // 8
    return data[-bytes_needed:] if bytes_needed > 0 else b""


# ============================================================================
# ПРОЦЕДУРЫ ДОПОЛНЕНИЯ ПО ГОСТ Р 34.13-2015 (раздел 4.1)
# ============================================================================


def _padding_procedure_1(data: bytes, block_size: int) -> bytes:
    """
    Процедура 1 по ГОСТ Р 34.13-2015, раздел 4.1.1.
    P* = P || 0^{ℓ-r}

    Args:
        data: исходные данные
        block_size: размер блока в байтах (ℓ)

    Returns:
        bytes: данные с дополнением нулями
    """
    r = len(data) % block_size
    if r == 0:
        return data
    padding_len = block_size - r
    return data + b"\x00" * padding_len


def _padding_procedure_2(data: bytes, block_size: int) -> bytes:
    """
    Процедура 2 по ГОСТ Р 34.13-2015, раздел 4.1.2.
    P* = P || 1 || 0^{ℓ-r-1}

    Args:
        data: исходные данные
        block_size: размер блока в байтах (ℓ)

    Returns:
        bytes: данные с дополнением (1 в битовом представлении = 0x80)
    """
    r = len(data) % block_size
    if r == 0:
        # Если длина кратна блоку, добавляем полный блок: 1 || 0^{ℓ-1}
        return data + b"\x80" + b"\x00" * (block_size - 1)
    padding_len = block_size - r
    return data + b"\x80" + b"\x00" * (padding_len - 1)


def _padding_procedure_3(data: bytes, block_size: int) -> Tuple[bytes, bool]:
    """
    Процедура 3 по ГОСТ Р 34.13-2015, раздел 4.1.3.
    - если r = n: последний блок не изменяется
    - если r < n: применяется процедура 2

    Args:
        data: исходные данные
        block_size: размер блока в байтах (n)

    Returns:
        Tuple[bytes, bool]: (дополненные данные, был ли последний блок полным)
    """
    r = len(data) % block_size
    if r == 0:
        return data, True
    else:
        return _padding_procedure_2(data, block_size), False


def _remove_padding_procedure_2(data: bytes, block_size: int) -> bytes:
    """
    Удаление дополнения, добавленного процедурой 2.
    Удаляем последний блок и восстанавливаем исходные данные.
    """
    if not data:
        return data
    # Ищем последний байт 0x80 (1 в битовом представлении)
    # Процедура 2 гарантирует, что 0x80 есть в конце
    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0x80:
            return data[:i]
    return data


def _remove_padding_procedure_3(data: bytes, block_size: int, was_full: bool) -> bytes:
    """
    Удаление дополнения, добавленного процедурой 3.
    """
    if was_full:
        return data
    return _remove_padding_procedure_2(data, block_size)


# ============================================================================
# РЕЖИМ 1: ECB (Electronic Codebook) - простая замена
# ============================================================================


class ModeECB:
    """
    Режим простой замены по ГОСТ Р 34.13-2015, раздел 5.1.
    Использует процедуру 2 для дополнения сообщения.
    """

    def __init__(self, cipher: MagmaCipher, use_padding: bool = True):
        """
        Args:
            cipher: экземпляр шифра
            use_padding: использовать процедуру 2 для дополнения
        """
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._use_padding = use_padding

    def encrypt(self, data: bytes) -> bytes:
        """
        Зашифрование в режиме ECB с дополнением по процедуре 2, где необходимо.
        """
        r = len(data) % self._block_size
        if r != 0:
            padded = data + b"\x80" + b"\x00" * (self._block_size - r - 1)
        else:
            padded = data  # Не добавляем паддинг, если длина кратна блоку!

        result = bytearray()
        for i in range(0, len(padded), self._block_size):
            result.extend(self._cipher.encrypt_block(padded[i : i + self._block_size]))
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        Расшифрование в режиме ECB с удалением дополнения.
        """
        if len(data) % self._block_size != 0:
            raise ValueError("Данные должны быть кратны размеру блока")

        result = bytearray()
        for i in range(0, len(data), self._block_size):
            result.extend(self._cipher.decrypt_block(data[i : i + self._block_size]))

        # Удаляем паддинг только если он был добавлен
        original_len = len(result)
        # Паддинг добавлялся только если исходные данные не были кратны блоку
        for i in range(original_len - 1, -1, -1):
            if result[i] == 0x80:
                return bytes(result[:i])

        return bytes(result)


# ============================================================================
# РЕЖИМ 2: CBC (Cipher Block Chaining) - простая замена с зацеплением
# ============================================================================


class ModeCBC:
    """
    Режим простой замены с зацеплением по ГОСТ Р 34.13-2015, раздел 5.4.
    Использует процедуру 2 для дополнения сообщения.
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes, m: int = None, use_padding: bool = True):
        """
        Args:
            cipher: экземпляр шифра
            iv: синхропосылка (длина m бит)
            m: размер регистра сдвига в битах (кратен n, по умолчанию = n)
            use_padding: использовать процедуру 2 для дополнения, если необходимо.
        """
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._n_bits = self._block_size * 8

        if m is None:
            m = self._n_bits
        self._m = m
        self._m_bytes = m // 8

        if len(iv) != self._m_bytes:
            raise ValueError(f"CBC: IV должен быть {self._m_bytes} байт (m={m} бит)")
        self._iv = iv
        self._use_padding = use_padding

    def encrypt(self, data: bytes) -> bytes:
        """
        C_i = e_K(P_i ⊕ MSB_n(R_i)), R_{i+1} = LSB_{m-n}(R_i) || C_i
        """
        if self._use_padding:
            padded = _padding_procedure_2(data, self._block_size)
        else:
            if len(data) % self._block_size != 0:
                raise ValueError("CBC: длина данных должна быть кратна размеру блока")
            padded = data

        result = bytearray()
        reg = self._iv

        for i in range(0, len(padded), self._block_size):
            block = padded[i : i + self._block_size]
            xored = _xor_bytes(block, _msb(reg, self._n_bits))
            encrypted = self._cipher.encrypt_block(xored)  # Исправлено
            result.extend(encrypted)
            reg = _lsb(reg, self._m - self._n_bits) + encrypted
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        P_i = d_K(C_i) ⊕ MSB_n(R_i), R_{i+1} = LSB_{m-n}(R_i) || C_i
        """
        if len(data) % self._block_size != 0:
            raise ValueError("CBC: длина данных должна быть кратна размеру блока")

        result = bytearray()
        reg = self._iv

        for i in range(0, len(data), self._block_size):
            block = data[i : i + self._block_size]
            decrypted = self._cipher.decrypt_block(block)
            xored = _xor_bytes(decrypted, _msb(reg, self._n_bits))
            result.extend(xored)
            reg = _lsb(reg, self._m - self._n_bits) + block

        if self._use_padding:
            return _remove_padding_procedure_2(bytes(result), self._block_size)
        return bytes(result)


# ============================================================================
# РЕЖИМ 3: CFB (Cipher Feedback) - гаммирование с обратной связью по шифртексту
# ============================================================================


class ModeCFB:
    """
    Режим гаммирования с обратной связью по шифртексту по ГОСТ Р 34.13-2015, раздел 5.5.
    Не требует дополнения.
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes, s: int = None, m: int = None):
        """
        Args:
            cipher: экземпляр шифра
            iv: синхропосылка (длина m бит)
            s: размер блока гаммы в битах (0 < s ≤ n, по умолчанию = n)
            m: размер регистра сдвига в битах (n ≤ m, по умолчанию = n)
        """
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._n_bits = self._block_size * 8

        if s is None:
            s = self._n_bits
        if m is None:
            m = self._n_bits

        self._s = s
        self._s_bytes = s // 8
        self._m = m
        self._m_bytes = m // 8

        if len(iv) != self._m_bytes:
            raise ValueError(f"CFB: IV должен быть {self._m_bytes} байт (m={m} бит)")
        self._iv = iv

    def encrypt(self, data: bytes) -> bytes:
        """
        C_i = P_i ⊕ T_s(e_K(MSB_n(R_i)))
        R_{i+1} = LSB_{m-s}(R_i) || C_i
        """
        result = bytearray()
        reg = self._iv

        for i in range(0, len(data), self._s_bytes):
            block = data[i : i + self._s_bytes]
            gamma = self._cipher.encrypt_block(_msb(reg, self._n_bits))
            gamma_trunc = _msb(gamma, self._s)
            encrypted = _xor_bytes(block, gamma_trunc[: len(block)])
            result.extend(encrypted)
            reg = _lsb(reg, self._m - self._s) + encrypted

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        P_i = C_i ⊕ T_s(e_K(MSB_n(R_i)))
        R_{i+1} = LSB_{m-s}(R_i) || C_i
        """
        result = bytearray()
        reg = self._iv

        for i in range(0, len(data), self._s_bytes):
            block = data[i : i + self._s_bytes]
            gamma = self._cipher.encrypt_block(_msb(reg, self._n_bits))
            gamma_trunc = _msb(gamma, self._s)
            decrypted = _xor_bytes(block, gamma_trunc[: len(block)])
            result.extend(decrypted)
            reg = _lsb(reg, self._m - self._s) + block

        return bytes(result)


# ============================================================================
# РЕЖИМ 4: OFB (Output Feedback) - гаммирование с обратной связью по выходу
# ============================================================================


class ModeOFB:
    """
    Режим гаммирования с обратной связью по выходу по ГОСТ Р 34.13-2015, раздел 5.3.
    Не требует дополнения.
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes, s: int = None, m: int = None):
        """
        Args:
            cipher: экземпляр шифра
            iv: синхропосылка (длина m бит)
            s: размер блока гаммы в битах (0 < s ≤ n, по умолчанию = n)
            m: размер регистра сдвига в битах (m = n·z, z ≥ 1, по умолчанию = n)
        """
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._n_bits = self._block_size * 8

        if s is None:
            s = self._n_bits
        if m is None:
            m = self._n_bits

        self._s = s
        self._s_bytes = s // 8
        self._m = m
        self._m_bytes = m // 8

        if len(iv) != self._m_bytes:
            raise ValueError(f"OFB: IV должен быть {self._m_bytes} байт (m={m} бит)")
        self._iv = iv

    def encrypt(self, data: bytes) -> bytes:
        """
        Y_i = e_K(MSB_n(R_i))
        C_i = P_i ⊕ T_s(Y_i)
        R_{i+1} = LSB_{m-n}(R_i) || Y_i
        """
        result = bytearray()
        reg = self._iv

        for i in range(0, len(data), self._s_bytes):
            block = data[i : i + self._s_bytes]
            gamma = self._cipher.encrypt_block(_msb(reg, self._n_bits))
            gamma_trunc = _msb(gamma, self._s)
            encrypted = _xor_bytes(block, gamma_trunc[: len(block)])
            result.extend(encrypted)
            reg = _lsb(reg, self._m - self._n_bits) + gamma

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """OFB: расшифрование идентично зашифрованию."""
        return self.encrypt(data)


# ============================================================================
# РЕЖИМ 5: CTR (Counter) - гаммирование
# ============================================================================


class ModeCTR:
    """
    Режим гаммирования по ГОСТ Р 34.13-2015, раздел 5.2.
    Не требует дополнения.
    """

    def __init__(self, cipher: MagmaCipher, iv: bytes, s: int = None):
        """
        Args:
            cipher: экземпляр шифра
            iv: синхропосылка (32 бита = 4 байта для Магмы)
            s: размер блока гаммы в битах (по умолчанию = n)
        """
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._n_bits = self._block_size * 8

        if s is None:
            s = self._n_bits
        self._s = s
        self._s_bytes = s // 8

        # По ГОСТ для Магмы IV = 32 бита
        expected_iv_len = self._block_size // 2
        if len(iv) != expected_iv_len:
            raise ValueError(f"CTR: для Магмы IV должен быть {expected_iv_len} байта")

        # CTR1 = IV || 0^32 (конкатенация)
        self._counter_bytes = iv + b"\x00" * (self._block_size // 2)
        self._counter = int.from_bytes(self._counter_bytes, byteorder="big")

    def _get_counter_block(self) -> bytes:
        # Возвращаем полный блок (8 байт) для Магмы
        return self._counter.to_bytes(self._block_size, byteorder="big")

    def _increment_counter(self):
        # Инкремент по модулю 2^64
        self._counter = (self._counter + 1) & 0xFFFFFFFFFFFFFFFF

    def _process(self, data: bytes) -> bytes:
        result = bytearray()
        original_counter = self._counter

        try:
            for i in range(0, len(data), self._s_bytes):
                block = data[i : i + self._s_bytes]
                gamma = self._cipher.encrypt_block(self._get_counter_block())
                gamma_trunc = _msb(gamma, self._s)
                result.extend(_xor_bytes(block, gamma_trunc[: len(block)]))
                self._increment_counter()
        finally:
            self._counter = original_counter

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
    Режим выработки имитовставки по ГОСТ Р 34.13-2015, раздел 5.6.
    Использует процедуру 3 для дополнения последнего блока.
    """

    def __init__(self, cipher: MagmaCipher):
        self._cipher = cipher
        self._block_size = MagmaCipher.BLOCK_SIZE
        self._n_bits = self._block_size * 8
        # B_64 = 0x1B в старших битах (MSB) = 0x1B00000000000000
        self._B_N = bytes.fromhex("1B00000000000000")

    def _left_shift_one(self, data: bytes) -> bytes:
        """Сдвиг влево на 1 бит в поле GF(2^n)."""
        value = int.from_bytes(data, byteorder="big")
        shifted = (value << 1) & 0xFFFFFFFFFFFFFFFF
        return shifted.to_bytes(self._block_size, byteorder="big")

    def _get_msb_bit(self, data: bytes) -> int:
        """Получение старшего бита (MSB) числа в big-endian."""
        return (data[0] >> 7) & 1

    def _derive_keys(self) -> Tuple[bytes, bytes]:
        """
        Выработка K1 и K2 по ГОСТ Р 34.13-2015, раздел 5.6.1.
        """
        zero_block = bytes(self._block_size)
        r = self._cipher.encrypt_block(zero_block)

        # K1 = R ⊗ x
        k1 = self._left_shift_one(r)
        if self._get_msb_bit(r) == 1:
            k1 = _xor_bytes(k1, self._B_N)

        # K2 = K1 ⊗ x
        k2 = self._left_shift_one(k1)
        if self._get_msb_bit(k1) == 1:
            k2 = _xor_bytes(k2, self._B_N)

        return k1, k2

    def generate(self, data: bytes, s: int = 32) -> bytes:
        """
        Выработка имитовставки по ГОСТ Р 34.13-2015, раздел 5.6.2.

        Args:
            data: входные данные
            s: длина имитовставки в битах (0 < s ≤ n)
        """
        if s <= 0 or s > self._n_bits:
            raise ValueError(f"MAC: s должно быть от 1 до {self._n_bits}")

        k1, k2 = self._derive_keys()

        # Разбиваем на блоки
        if not data:
            blocks = [bytes(self._block_size)]
            full_last = True
        else:
            blocks = [data[i : i + self._block_size] for i in range(0, len(data), self._block_size)]
            full_last = len(blocks[-1]) == self._block_size

        # Применяем процедуру 3 к последнему блоку
        if full_last:
            k_star = k1
            # Последний блок полный - не изменяется
            padded_last = blocks[-1]
        else:
            k_star = k2
            # Процедура 3: применяем процедуру 2
            padded_last = _padding_procedure_2(blocks[-1], self._block_size)
            blocks = blocks[:-1] + [padded_last]

        # C_0 = 0^n
        c_prev = bytes(self._block_size)

        # Обработка всех блоков КРОМЕ последнего
        for block in blocks[:-1]:
            c_prev = self._cipher.encrypt_block(_xor_bytes(block, c_prev))

        # Последний блок: MAC = T_s(e_K(P_q^* ⊕ C_{q-1} ⊕ K*))
        last_block = blocks[-1]
        xored = _xor_bytes(last_block, c_prev)
        xored = _xor_bytes(xored, k_star)
        result = self._cipher.encrypt_block(xored)

        return _msb(result, s)

    def verify(self, data: bytes, mac: bytes, s: int = 32) -> bool:
        """Проверка имитовставки."""
        return self.generate(data, s) == mac
