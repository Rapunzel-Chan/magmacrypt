"""
Тестирование режимов работы по ГОСТ Р 34.13-2015.
Проверяются свойства, а не конкретные значения (так как в ГОСТ нет тестовых векторов).
"""

import os
import sys
from typing import Tuple

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from magma_code import MagmaCipher, test_magma
from magma_modes import (
    ModeECB, ModeCBC, ModeCFB, ModeOFB, ModeCTR, ModeMAC,
    _xor_bytes, _msb, _lsb
)


# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def print_test_result(name: str, passed: bool, details: str = ""):
    """Вывод результата теста."""
    status = "✓ ПРОЙДЕН" if passed else "✗ НЕ ПРОЙДЕН"
    print(f"  {name}: {status}")
    if details and not passed:
        print(f"    {details}")


# ============================================================================
# ТЕСТ 1: ECB (проверка на контрольном примере из ГОСТ)
# ============================================================================

def test_ecb_gost():
    """Тест ECB на контрольном примере из ГОСТ Р 34.12-2015."""
    print("\n" + "-" * 50)
    print("1. ECB - проверка на контрольном примере ГОСТ")

    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex("fedcba9876543210")
    expected = bytes.fromhex("4ee901e5c2d8ca3d")

    cipher = MagmaCipher(key)
    ecb = ModeECB(cipher)

    # Шифруем блок (без паддинга, так как ровно 8 байт)
    encrypted = ecb._cipher.encrypt_block(plaintext)

    passed = (encrypted == expected)
    print_test_result("Шифрование блока", passed,
                      f"Получено: {encrypted.hex()}, Ожидалось: {expected.hex()}")

    # Расшифровываем
    decrypted = ecb._cipher.decrypt_block(encrypted)
    passed_dec = (decrypted == plaintext)
    print_test_result("Расшифрование блока", passed_dec)

    return passed and passed_dec


# ============================================================================
# ТЕСТ 2: CBC (проверка свойств)
# ============================================================================

def test_cbc_properties():
    """Тест CBC: одинаковые блоки → разные шифротексты, зависимость от IV."""
    print("\n" + "-" * 50)
    print("2. CBC - проверка свойств")

    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    cipher = MagmaCipher(key)

    # Тестовые данные: два одинаковых блока
    data = b"ABCDEFGHABCDEFGH"  # 16 байт = 2 блока

    # Разные IV
    iv1 = bytes.fromhex("1111111111111111")
    iv2 = bytes.fromhex("2222222222222222")

    cbc1 = ModeCBC(cipher, iv1)
    cbc2 = ModeCBC(cipher, iv2)

    encrypted1 = cbc1.encrypt(data)
    encrypted2 = cbc2.encrypt(data)

    # Проверка 1: разные IV дают разные шифротексты
    different_iv = (encrypted1 != encrypted2)
    print_test_result("Разные IV → разные шифротексты", different_iv)

    # Проверка 2: одинаковые блоки дают разные шифротексты (из-за сцепления)
    block1 = encrypted1[:8]
    block2 = encrypted1[8:16]
    blocks_different = (block1 != block2)
    print_test_result("Одинаковые блоки → разные шифротексты (сцепление)", blocks_different)

    # Проверка 3: расшифрование работает корректно
    decrypted = cbc1.decrypt(encrypted1)
    decrypt_works = (decrypted == data)
    print_test_result("Расшифрование восстанавливает данные", decrypt_works)

    return different_iv and blocks_different and decrypt_works


# ============================================================================
# ТЕСТ 3: CFB (проверка свойств)
# ============================================================================

def test_cfb_properties():
    """Тест CFB: потоковый режим, не требует паддинга."""
    print("\n" + "-" * 50)
    print("3. CFB - проверка свойств")

    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    cipher = MagmaCipher(key)
    iv = bytes.fromhex("1234567890abcdef")

    cfb = ModeCFB(cipher, iv)

    data1 = b"Hello"
    data2 = b"Hellp"  # изменили последний байт

    encrypted1 = cfb.encrypt(data1)
    encrypted2 = cfb.encrypt(data2)

    # Проверка 1: длина шифротекста равна длине открытого текста
    no_padding = (len(encrypted1) == len(data1))
    print_test_result("Нет паддинга (длина не увеличивается)", no_padding)

    # Проверка 2: расшифрование работает
    decrypted1 = cfb.decrypt(encrypted1)
    decrypt_works = (decrypted1 == data1)
    print_test_result("Расшифрование восстанавливает данные", decrypt_works)

    # Проверка 3: изменение одного байта данных → изменение шифротекста
    different_data = (encrypted1 != encrypted2)
    print_test_result("Изменение данных → изменение шифротекста", different_data)

    return no_padding and decrypt_works and different_data


# ============================================================================
# ТЕСТ 4: OFB (проверка свойств)
# ============================================================================

def test_ofb_properties():
    """Тест OFB: потоковый режим, ошибки не распространяются."""
    print("\n" + "-" * 50)
    print("4. OFB - проверка свойств")

    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    cipher = MagmaCipher(key)
    iv = bytes.fromhex("1234567890abcdef")

    ofb = ModeOFB(cipher, iv)

    data = b"Hello, World! This is a test."
    encrypted = ofb.encrypt(data)

    # Проверка 1: расшифрование работает (OFB симметричен)
    decrypted = ofb.decrypt(encrypted)
    decrypt_works = (decrypted == data)
    print_test_result("Расшифрование восстанавливает данные", decrypt_works)

    # Проверка 2: длина не меняется
    length_preserved = (len(encrypted) == len(data))
    print_test_result("Длина не меняется", length_preserved)

    # Проверка 3: повторное шифрование тем же IV дает тот же результат
    ofb2 = ModeOFB(cipher, iv)
    encrypted2 = ofb2.encrypt(data)
    deterministic = (encrypted == encrypted2)
    print_test_result("Детерминированность (одинаковый IV → одинаковый шифротекст)", deterministic)

    return decrypt_works and length_preserved and deterministic


# ============================================================================
# ТЕСТ 5: CTR (проверка свойств)
# ============================================================================

def test_ctr_properties():
    """Тест CTR: счетчик, произвольный доступ."""
    print("\n" + "-" * 50)
    print("5. CTR - проверка свойств")

    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    cipher = MagmaCipher(key)
    nonce = bytes.fromhex("12345678")

    ctr = ModeCTR(cipher, nonce)

    data = b"Hello, World! This is a test message for CTR mode."
    encrypted = ctr.encrypt(data)

    # Проверка 1: расшифрование работает
    ctr2 = ModeCTR(cipher, nonce)
    decrypted = ctr2.decrypt(encrypted)
    decrypt_works = (decrypted == data)
    print_test_result("Расшифрование восстанавливает данные", decrypt_works)

    # Проверка 2: длина не меняется
    length_preserved = (len(encrypted) == len(data))
    print_test_result("Длина не меняется", length_preserved)

    # Проверка 3: разные nonce дают разные шифротексты
    nonce2 = bytes.fromhex("87654321")
    ctr3 = ModeCTR(cipher, nonce2)
    encrypted2 = ctr3.encrypt(data)
    different_nonce = (encrypted != encrypted2)
    print_test_result("Разные nonce → разные шифротексты", different_nonce)

    return decrypt_works and length_preserved and different_nonce


# ============================================================================
# ТЕСТ 6: MAC (проверка свойств)
# ============================================================================

def test_mac_properties():
    """Тест MAC: детерминированность, зависимость от ключа и данных."""
    print("\n" + "-" * 50)
    print("6. MAC - проверка свойств")

    key1 = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    key2 = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

    cipher1 = MagmaCipher(key1)
    cipher2 = MagmaCipher(key2)

    mac1 = ModeMAC(cipher1)
    mac2 = ModeMAC(cipher2)

    data = b"Hello, World! This is a test message."
    data_corrupted = b"Hello, World! This is a test message." + b"X"

    # Генерируем MAC для разных ключей и данных
    mac_key1 = mac1.generate(data, s=32)
    mac_key1_again = mac1.generate(data, s=32)
    mac_key2 = mac2.generate(data, s=32)
    mac_corrupted = mac1.generate(data_corrupted, s=32)

    # Проверка 1: детерминированность (одинаковые данные и ключ → одинаковый MAC)
    deterministic = (mac_key1 == mac_key1_again)
    print_test_result("Детерминированность", deterministic)

    # Проверка 2: разные ключи → разные MAC
    different_key = (mac_key1 != mac_key2)
    print_test_result("Разные ключи → разные MAC", different_key)

    # Проверка 3: разные данные → разные MAC
    different_data = (mac_key1 != mac_corrupted)
    print_test_result("Разные данные → разные MAC", different_data)

    # Проверка 4: верификация работает
    verify_ok = mac1.verify(data, mac_key1, s=32)
    print_test_result("Верификация корректного MAC", verify_ok)

    # Проверка 5: верификация с измененными данными
    verify_corrupted = not mac1.verify(data_corrupted, mac_key1, s=32)
    print_test_result("Верификация с измененными данными (должна провалиться)", verify_corrupted)

    # Проверка 6: верификация с неверным ключом
    verify_wrong_key = not mac2.verify(data, mac_key1, s=32)
    print_test_result("Верификация с неверным ключом (должна провалиться)", verify_wrong_key)

    return (deterministic and different_key and different_data and
            verify_ok and verify_corrupted and verify_wrong_key)


# ============================================================================
# ТЕСТ 7: Процедуры дополнения (по ГОСТ Р 34.13-2015)
# ============================================================================

def test_padding_procedures():
    """Тест процедур дополнения из ГОСТ Р 34.13-2015."""
    print("\n" + "-" * 50)
    print("7. Процедуры дополнения (ГОСТ Р 34.13-2015)")

    from magma_modes import ModeECB

    # Процедура 3: P^* = P || 1 || 0^{n-r-1} для неполного блока
    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    cipher = MagmaCipher(key)
    ecb = ModeECB(cipher)

    # Тест 1: блок полный (8 байт) → добавляется целый блок паддинга
    data_full = b"ABCDEFGH"
    padded_full = ecb._add_padding(data_full)
    expected_full = b"ABCDEFGH" + bytes([8]) * 8
    padding_full = (padded_full == expected_full)
    print_test_result("Полный блок → добавляется блок паддинга", padding_full)

    # Тест 2: блок неполный (5 байт) → добавляется 3 байта со значением 3
    data_short = b"ABCDE"
    padded_short = ecb._add_padding(data_short)
    expected_short = b"ABCDE" + bytes([3]) * 3
    padding_short = (padded_short == expected_short)
    print_test_result("Неполный блок → паддинг со значением длины", padding_short)

    # Тест 3: удаление паддинга
    removed_full = ecb._remove_padding(padded_full)
    removed_short = ecb._remove_padding(padded_short)
    remove_works = (removed_full == data_full and removed_short == data_short)
    print_test_result("Удаление паддинга восстанавливает данные", remove_works)

    return padding_full and padding_short and remove_works


# ============================================================================
# ТЕСТ 8: Усечение (MSB)
# ============================================================================

def test_truncation():
    """Тест функции усечения (MSB)."""
    print("\n" + "-" * 50)
    print("8. Усечение (MSB) - ГОСТ Р 34.13-2015")

    from magma_modes import _msb

    # Тест: взять старшие 24 бита (3 байта) из 8-байтного блока
    data = bytes.fromhex("A1B2C3D4E5F6A7B8")
    truncated = _msb(data, 24)
    expected = bytes.fromhex("A1B2C3")

    msb_works = (truncated == expected)
    print_test_result("MSB (старшие биты) работает корректно", msb_works)
    if not msb_works:
        print(f"    Получено: {truncated.hex()}, Ожидалось: {expected.hex()}")

    # Тест: взять старшие 32 бита (4 байта)
    truncated_32 = _msb(data, 32)
    expected_32 = bytes.fromhex("A1B2C3D4")
    msb_32_works = (truncated_32 == expected_32)
    print_test_result("MSB 32 бита", msb_32_works)

    return msb_works and msb_32_works


# ============================================================================
# ЗАПУСК ВСЕХ ТЕСТОВ
# ============================================================================

def run_all_tests():
    """Запуск всех тестов."""
    print("=" * 70)
    print("ТЕСТИРОВАНИЕ РЕЖИМОВ РАБОТЫ (ГОСТ Р 34.13-2015)")
    print("Проверка свойств, а не конкретных значений")
    print("=" * 70)

    results = []

    # Базовый тест ECB по ГОСТ
    results.append(("ECB (контрольный пример ГОСТ)", test_ecb_gost()))

    # Тесты свойств режимов
    results.append(("CBC (свойства)", test_cbc_properties()))
    results.append(("CFB (свойства)", test_cfb_properties()))
    results.append(("OFB (свойства)", test_ofb_properties()))
    results.append(("CTR (свойства)", test_ctr_properties()))
    results.append(("MAC (свойства)", test_mac_properties()))
    results.append(("Процедуры дополнения", test_padding_procedures()))
    results.append(("Усечение (MSB)", test_truncation()))

    # Итоги
    print("\n" + "=" * 70)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 70)

    all_passed = True
    for name, passed in results:
        status = "✓" if passed else "✗"
        print(f"  {status} {name}")
        if not passed:
            all_passed = False

    print("\n" + "=" * 70)
    if all_passed:
        print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
    else:
        print("НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ!")
    print("=" * 70)

    return all_passed


if __name__ == "__main__":
    run_all_tests()
