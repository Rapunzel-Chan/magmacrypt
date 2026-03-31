"""
Тестирование режимов работы шифра Магма по ГОСТ Р 34.13-2015
с использованием pytest.

Контрольные примеры из Приложения А.2 (стр. 35-40) ГОСТ Р 34.13-2015
"""

import pytest

from magma_code import MagmaCipher
from magma_modes import ModeCBC, ModeCFB, ModeCTR, ModeECB, ModeMAC, ModeOFB, _lsb, _msb, _xor_bytes

# ============================================================================
# ФИКСТУРЫ
# ============================================================================


@pytest.fixture
def key() -> bytes:
    """Ключ из ГОСТ Р 34.13-2015, Приложение А.2"""
    return bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")


@pytest.fixture
def cipher(key) -> MagmaCipher:
    """Экземпляр шифра Магма с ключом из ГОСТ"""
    return MagmaCipher(key)


# ============================================================================
# ТЕСТЫ ECB (Electronic Codebook) - Таблица А.7, стр. 35
# ============================================================================


class TestECB:
    """Режим простой замены (Electronic Codebook)"""

    # Контрольные пары (открытый текст, шифртекст) из Таблицы А.7
    TEST_VECTORS = [
        ("92def06b3c130a59", "2b073f0494f372a0"),
        ("db54c704f8189d20", "de70e715d3556e48"),
        ("4a98fb2e67a8024c", "11d8d9e9eacfbc1e"),
        ("8912409b17b57e41", "7c68260996c67efb"),
    ]

    def test_encrypt(self, cipher):
        """Проверка зашифрования для каждого блока"""
        ecb = ModeECB(cipher, use_padding=False)

        for plain_hex, expected_hex in self.TEST_VECTORS:
            plain = bytes.fromhex(plain_hex)
            expected = bytes.fromhex(expected_hex)
            result = ecb.encrypt(plain)
            assert result == expected, f"ECB encrypt failed for {plain_hex}"

    def test_decrypt(self, cipher):
        """Проверка расшифрования для каждого блока"""
        ecb = ModeECB(cipher, use_padding=False)

        for plain_hex, expected_hex in self.TEST_VECTORS:
            ciphertext = bytes.fromhex(expected_hex)
            expected = bytes.fromhex(plain_hex)
            result = ecb.decrypt(ciphertext)
            assert result == expected, f"ECB decrypt failed for {expected_hex}"

    def test_encrypt_decrypt_roundtrip(self, cipher):
        """Проверка цикла: зашифрование -> расшифрование"""
        ecb = ModeECB(cipher, use_padding=False)
        test_data = bytes.fromhex("92def06b3c130a59db54c704f8189d20")

        encrypted = ecb.encrypt(test_data)
        decrypted = ecb.decrypt(encrypted)

        assert decrypted == test_data, "ECB roundtrip failed"

    def test_padding(self, cipher):
        """Проверка работы с паддингом (процедура 2)"""
        ecb = ModeECB(cipher, use_padding=True)

        # Данные не кратные блоку (7 байт)
        test_data = b"Hello12"  # 7 байт
        encrypted = ecb.encrypt(test_data)
        decrypted = ecb.decrypt(encrypted)
        assert decrypted == test_data, "ECB with padding failed"

        # Пустые данные
        test_data = b""
        encrypted = ecb.encrypt(test_data)
        decrypted = ecb.decrypt(encrypted)
        assert decrypted == test_data, "ECB with empty data failed"


# ============================================================================
# ТЕСТЫ CBC (Cipher Block Chaining) - Таблица А.10, стр. 38
# ============================================================================


class TestCBC:
    """Режим простой замены с зацеплением (Cipher Block Chaining)"""

    # Контрольные пары из Таблицы А.10
    TEST_VECTORS = [
        ("92def06b3c130a59", "96d1b05eea683919"),
        ("db54c704f8189d20", "aff76129abb937b9"),
        ("4a98fb2e67a8024c", "5058b4a1c4bc0019"),
        ("8912409b17b57e41", "20b78b1a7cd7e667"),
    ]

    IV = bytes.fromhex("1234567890abcdef234567890abcdef134567890abcdef12")  # m=192 бит
    M_BITS = 192

    def test_encrypt(self, cipher):
        """Проверка зашифрования для каждого блока"""
        cbc = ModeCBC(cipher, self.IV, m=self.M_BITS, use_padding=False)

        all_plain = b""
        all_expected = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_expected += bytes.fromhex(expected_hex)

        result = cbc.encrypt(all_plain)
        assert result == all_expected, f"CBC encrypt failed"

    def test_decrypt(self, cipher):
        """Проверка расшифрования для каждого блока"""
        cbc = ModeCBC(cipher, self.IV, m=self.M_BITS, use_padding=False)

        all_plain = b""
        all_ciphertext = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_ciphertext += bytes.fromhex(expected_hex)

        result = cbc.decrypt(all_ciphertext)
        assert result == all_plain, f"CBC decrypt failed"

    def test_encrypt_decrypt_roundtrip(self, cipher):
        """Проверка цикла: зашифрование -> расшифрование"""
        cbc = ModeCBC(cipher, self.IV, m=self.M_BITS, use_padding=False)
        test_data = bytes.fromhex("92def06b3c130a59" "db54c704f8189d20" "4a98fb2e67a8024c")

        encrypted = cbc.encrypt(test_data)
        decrypted = cbc.decrypt(encrypted)

        assert decrypted == test_data, "CBC roundtrip failed"

    def test_different_iv(self, cipher):
        """Проверка, что разные IV дают разные результаты"""
        cbc1 = ModeCBC(cipher, self.IV, m=self.M_BITS, use_padding=False)
        cbc2 = ModeCBC(cipher, bytes(24), m=self.M_BITS, use_padding=False)  # нулевой IV

        test_data = bytes.fromhex("92def06b3c130a59")

        result1 = cbc1.encrypt(test_data)
        result2 = cbc2.encrypt(test_data)

        assert result1 != result2, "Different IVs should produce different ciphertexts"


# ============================================================================
# ТЕСТЫ CTR (Counter) - Таблица А.8, стр. 36
# ============================================================================


class TestCTR:
    """Режим гаммирования (Counter)"""

    # Контрольные пары из Таблицы А.8
    TEST_VECTORS = [
        ("92def06b3c130a59", "4e98110c97b7b93c"),
        ("db54c704f8189d20", "3e250d93d6e85d69"),
        ("4a98fb2e67a8024c", "136d868807b2dbef"),
        ("8912409b17b57e41", "568eb680ab52a12d"),
    ]

    IV = bytes.fromhex("12345678")  # 32 бита для Магмы

    def test_encrypt(self, cipher):
        """Проверка зашифрования"""
        ctr = ModeCTR(cipher, self.IV)

        all_plain = b""
        all_expected = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_expected += bytes.fromhex(expected_hex)

        result = ctr.encrypt(all_plain)
        assert result == all_expected, f"CTR encrypt failed"

    def test_decrypt(self, cipher):
        """Проверка расшифрования (должно быть идентично зашифрованию)"""
        ctr = ModeCTR(cipher, self.IV)

        all_plain = b""
        all_ciphertext = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_ciphertext += bytes.fromhex(expected_hex)

        result = ctr.decrypt(all_ciphertext)
        assert result == all_plain, f"CTR decrypt failed"

    def test_encrypt_decrypt_roundtrip(self, cipher):
        """Проверка цикла: зашифрование -> расшифрование"""
        ctr = ModeCTR(cipher, self.IV)
        test_data = bytes.fromhex("92def06b3c130a59" "db54c704f8189d20" "4a98fb2e67a8024c")

        encrypted = ctr.encrypt(test_data)
        decrypted = ctr.decrypt(encrypted)

        assert decrypted == test_data, "CTR roundtrip failed"

    def test_counter_increment(self, cipher):
        """Проверка инкрементации счетчика"""
        ctr = ModeCTR(cipher, self.IV)

        # Получаем первый блок
        block1 = ctr._get_counter_block()
        ctr._increment_counter()
        block2 = ctr._get_counter_block()

        # Счетчик должен увеличиться на 1
        val1 = int.from_bytes(block1, "big")
        val2 = int.from_bytes(block2, "big")
        assert val2 == val1 + 1, "Counter increment failed"


# ============================================================================
# ТЕСТЫ CFB (Cipher Feedback) - Таблица А.11, стр. 39
# ============================================================================


class TestCFB:
    """Режим гаммирования с обратной связью по шифртексту"""

    # Контрольные пары из Таблицы А.11
    TEST_VECTORS = [
        ("92def06b3c130a59", "db37e0e266903c83"),
        ("db54c704f8189d20", "0d46644c1f9a089c"),
        ("4a98fb2e67a8024c", "24bdd2035315d38b"),
        ("8912409b17b57e41", "bcc0321421075505"),
    ]

    IV = bytes.fromhex("1234567890abcdef234567890abcdef1")  # m=128 бит
    S_BITS = 64  # s = n = 64 бит
    M_BITS = 128  # m = 2n = 128 бит

    def test_encrypt(self, cipher):
        """Проверка зашифрования для каждого блока"""
        cfb = ModeCFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)

        all_plain = b""
        all_expected = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_expected += bytes.fromhex(expected_hex)

        result = cfb.encrypt(all_plain)
        assert result == all_expected, f"CFB encrypt failed"

    def test_decrypt(self, cipher):
        """Проверка расшифрования"""
        cfb = ModeCFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)

        all_plain = b""
        all_ciphertext = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_ciphertext += bytes.fromhex(expected_hex)

        result = cfb.decrypt(all_ciphertext)
        assert result == all_plain, f"CFB decrypt failed"

    def test_encrypt_decrypt_roundtrip(self, cipher):
        """Проверка цикла: зашифрование -> расшифрование"""
        cfb = ModeCFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)
        test_data = bytes.fromhex("92def06b3c130a59" "db54c704f8189d20")

        encrypted = cfb.encrypt(test_data)
        decrypted = cfb.decrypt(encrypted)

        assert decrypted == test_data, "CFB roundtrip failed"

    @pytest.mark.parametrize("s", [8, 16, 32, 64])
    def test_different_s(self, cipher, s):
        """Проверка работы с разными размерами блока гаммы s"""
        cfb = ModeCFB(cipher, self.IV, s=s, m=self.M_BITS)
        test_data = bytes.fromhex("92def06b3c130a59")

        encrypted = cfb.encrypt(test_data)
        decrypted = cfb.decrypt(encrypted)

        assert decrypted == test_data, f"CFB with s={s} failed"


# ============================================================================
# ТЕСТЫ OFB (Output Feedback) - Таблица А.9, стр. 37
# ============================================================================


class TestOFB:
    """Режим гаммирования с обратной связью по выходу"""

    # Контрольные пары из Таблицы А.9
    TEST_VECTORS = [
        ("92def06b3c130a59", "db37e0e266903c83"),
        ("db54c704f8189d20", "0d46644c1f9a089c"),
        ("4a98fb2e67a8024c", "a0f83062430e327e"),
        ("8912409b17b57e41", "c824efb8bd4fdb05"),
    ]

    IV = bytes.fromhex("1234567890abcdef234567890abcdef1")  # m=128 бит
    S_BITS = 64  # s = n = 64 бит
    M_BITS = 128  # m = 2n = 128 бит

    def test_encrypt(self, cipher):
        """Проверка зашифрования"""
        ofb = ModeOFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)

        all_plain = b""
        all_expected = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_expected += bytes.fromhex(expected_hex)

        result = ofb.encrypt(all_plain)
        assert result == all_expected, f"OFB encrypt failed"

    def test_decrypt(self, cipher):
        """Проверка расшифрования (OFB: encrypt == decrypt)"""
        ofb = ModeOFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)

        all_plain = b""
        all_ciphertext = b""
        for plain_hex, expected_hex in self.TEST_VECTORS:
            all_plain += bytes.fromhex(plain_hex)
            all_ciphertext += bytes.fromhex(expected_hex)

        # В OFB расшифрование идентично зашифрованию
        result = ofb.decrypt(all_ciphertext)
        assert result == all_plain, f"OFB decrypt failed"

    def test_encrypt_decrypt_roundtrip(self, cipher):
        """Проверка цикла: зашифрование -> расшифрование"""
        ofb = ModeOFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)
        test_data = bytes.fromhex("92def06b3c130a59" "db54c704f8189d20")

        encrypted = ofb.encrypt(test_data)
        decrypted = ofb.decrypt(encrypted)

        assert decrypted == test_data, "OFB roundtrip failed"

    def test_encrypt_equals_decrypt(self, cipher):
        """Проверка свойства OFB: encrypt == decrypt"""
        ofb = ModeOFB(cipher, self.IV, s=self.S_BITS, m=self.M_BITS)
        test_data = bytes.fromhex("92def06b3c130a59")

        encrypted = ofb.encrypt(test_data)
        decrypted = ofb.decrypt(encrypted)

        # Дважды зашифровать = расшифровать
        double_encrypted = ofb.encrypt(encrypted)
        assert double_encrypted == test_data, "OFB: double encryption should decrypt"


# ============================================================================
# ТЕСТЫ MAC (Message Authentication Code) - Таблица А.12, стр. 40
# ============================================================================


class TestMAC:
    """Режим выработки имитовставки"""

    # Контрольные данные из Таблицы А.12
    TEST_DATA = bytes.fromhex("92def06b3c130a59" "db54c704f8189d20" "4a98fb2e67a8024c" "8912409b17b57e41")
    EXPECTED_MAC_32 = bytes.fromhex("154e7210")  # 32 бита
    EXPECTED_MAC_64 = bytes.fromhex("154e72102030c5bb")  # 64 бита (из таблицы)

    def test_generate_32bit(self, cipher):
        """Проверка генерации 32-битного MAC"""
        mac = ModeMAC(cipher)
        result = mac.generate(self.TEST_DATA, s=32)
        assert result == self.EXPECTED_MAC_32, f"MAC 32-bit generation failed"

    def test_generate_64bit(self, cipher):
        """Проверка генерации 64-битного MAC (полный блок)"""
        mac = ModeMAC(cipher)
        result = mac.generate(self.TEST_DATA, s=64)
        assert result == self.EXPECTED_MAC_64, f"MAC 64-bit generation failed"

    def test_verify_correct(self, cipher):
        """Проверка верификации корректного MAC"""
        mac = ModeMAC(cipher)
        assert mac.verify(self.TEST_DATA, self.EXPECTED_MAC_32, s=32) is True

    def test_verify_incorrect(self, cipher):
        """Проверка верификации некорректного MAC"""
        mac = ModeMAC(cipher)
        wrong_mac = bytes.fromhex("00000000")
        assert mac.verify(self.TEST_DATA, wrong_mac, s=32) is False

    def test_verify_modified_data(self, cipher):
        """Проверка, что изменение данных приводит к неверному MAC"""
        mac = ModeMAC(cipher)
        modified_data = self.TEST_DATA[:-1] + bytes([self.TEST_DATA[-1] ^ 0xFF])
        assert mac.verify(modified_data, self.EXPECTED_MAC_32, s=32) is False

    def test_empty_message(self, cipher):
        """Проверка генерации MAC для пустого сообщения"""
        mac = ModeMAC(cipher)
        result = mac.generate(b"", s=32)
        # Для пустого сообщения MAC не должен быть нулевым
        assert result != bytes(4), "MAC for empty message should not be zero"
        assert len(result) == 4, "MAC length should be 4 bytes for s=32"

    def test_different_s_values(self, cipher):
        """Проверка MAC с разными длинами"""
        mac = ModeMAC(cipher)

        for s in [8, 16, 24, 32, 40, 48, 56, 64]:
            result = mac.generate(self.TEST_DATA, s=s)
            assert len(result) == (s + 7) // 8, f"MAC length mismatch for s={s}"
            # Проверяем, что результат не нулевой
            assert result != bytes(len(result)), f"MAC for s={s} should not be zero"

    def test_auxiliary_keys(self, cipher):
        """Проверка выработки вспомогательных ключей K1 и K2"""
        mac = ModeMAC(cipher)
        k1, k2 = mac._derive_keys()

        # K1 и K2 должны быть разными
        assert k1 != k2, "K1 and K2 should be different"
        # Длина каждого - 8 байт (64 бита)
        assert len(k1) == 8, "K1 should be 8 bytes"
        assert len(k2) == 8, "K2 should be 8 bytes"


# ============================================================================
# КРОСС-РЕЖИМНЫЕ ТЕСТЫ
# ============================================================================


class TestCrossMode:
    """Тесты, проверяющие корректность работы между режимами"""

    def test_ecb_cbc_consistency(self, cipher):
        """Проверка, что ECB и CBC с нулевым IV дают разные результаты"""
        test_data = bytes.fromhex("92def06b3c130a59" * 2)

        ecb = ModeECB(cipher, use_padding=False)
        cbc = ModeCBC(cipher, bytes(8), m=64, use_padding=False)

        ecb_result = ecb.encrypt(test_data)
        cbc_result = cbc.encrypt(test_data)

        # Результаты должны отличаться (CBC с нулевым IV дает эффект зацепления)
        assert ecb_result != cbc_result, "ECB and CBC should produce different results"

    def test_cfb_ofb_are_different_modes(self, cipher):
        """Проверка, что CFB и OFB - это разные режимы (результаты отличаются для длинных данных)"""
        # Используем 10 блоков данных
        single_block = bytes.fromhex("92def06b3c130a59")
        test_data = single_block * 10
        iv = bytes.fromhex("1234567890abcdef234567890abcdef1")

        cfb = ModeCFB(cipher, iv, s=64, m=128)
        ofb = ModeOFB(cipher, iv, s=64, m=128)

        cfb_result = cfb.encrypt(test_data)
        ofb_result = ofb.encrypt(test_data)

        # Для длинных данных результаты должны отличаться
        assert (
            cfb_result != ofb_result
        ), f"CFB and OFB should differ for long data. First 16 bytes: CFB={cfb_result[:16].hex()}, OFB={ofb_result[:16].hex()}"

    def test_ctr_consistency_with_different_iv(self, cipher):
        """Проверка, что разные IV в CTR дают разные результаты"""
        test_data = bytes.fromhex("92def06b3c130a59")

        ctr1 = ModeCTR(cipher, bytes.fromhex("00000000"))
        ctr2 = ModeCTR(cipher, bytes.fromhex("00000001"))

        result1 = ctr1.encrypt(test_data)
        result2 = ctr2.encrypt(test_data)

        assert result1 != result2, "Different IVs in CTR should produce different results"


# ============================================================================
# ТЕСТЫ ВСПОМОГАТЕЛЬНЫХ ФУНКЦИЙ
# ============================================================================


class TestHelperFunctions:
    """Тесты вспомогательных функций из magma_modes"""

    def test_xor_bytes(self):
        """Проверка функции XOR байтов"""
        a = bytes.fromhex("12345678")
        b = bytes.fromhex("87654321")
        # 0x12 ^ 0x87 = 0x95
        # 0x34 ^ 0x65 = 0x51
        # 0x56 ^ 0x43 = 0x15
        # 0x78 ^ 0x21 = 0x59
        expected = bytes.fromhex("95511559")
        assert _xor_bytes(a, b) == expected

        # Проверка с разной длиной - должно быть исключение
        with pytest.raises(ValueError, match="длины не совпадают"):
            _xor_bytes(b"123", b"12")

    def test_msb(self):
        """Проверка взятия старших битов (MSB)"""
        data = bytes.fromhex("1234567890ABCDEF")
        # 8 бит = 1 байт
        assert _msb(data, 8) == bytes.fromhex("12")
        # 16 бит = 2 байта
        assert _msb(data, 16) == bytes.fromhex("1234")
        # 32 бита = 4 байта
        assert _msb(data, 32) == bytes.fromhex("12345678")
        # 64 бита = 8 байт (все данные)
        assert _msb(data, 64) == data

    def test_lsb(self):
        """Проверка взятия младших битов (LSB)"""
        data = bytes.fromhex("1234567890ABCDEF")
        # 8 бит = 1 байт
        assert _lsb(data, 8) == bytes.fromhex("EF")
        # 16 бит = 2 байта
        assert _lsb(data, 16) == bytes.fromhex("CDEF")
        # 32 бита = 4 байта
        assert _lsb(data, 32) == bytes.fromhex("90ABCDEF")
        # 64 бита = 8 байт (все данные)
        assert _lsb(data, 64) == data


# ============================================================================
# ЗАПУСК ТЕСТОВ
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
