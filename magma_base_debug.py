"""
Отладочная версия шифра Магма с пошаговым выводом.
Позволяет проследить все этапы шифрования и сверить с ГОСТ.
"""

import sys
from typing import Tuple

from magma_code import MagmaCipher, MagmaSBoxes, MagmaKeySchedule


class MagmaCipherDebug(MagmaCipher):
    """
    Отладочная версия шифра с выводом промежуточных значений.
    """

    def encrypt_block_debug(self, plaintext: bytes) -> bytes:
        """Шифрование блока с пошаговым отладочным выводом."""
        # ШАГ 1: Разделение блока на левую и правую половины
        left, right = self._bytes_to_halves(plaintext)

        print("\n" + "=" * 80)
        print(f"НАЧАЛО ЗАШИФРОВАНИЯ БЛОКА: {plaintext.hex()}")
        print("=" * 80)
        print(f"\nШАГ 1: Разделение блока на половины")
        print(f"  Блок (8 байт): {plaintext.hex()}")
        print(f"  Левая половина L0 = 0x{left:08X}")
        print(f"  Правая половина R0 = 0x{right:08X}")

        # ШАГ 2: 32 раунда сети Фейстеля
        print("\n" + "=" * 80)
        print("ШАГ 2: Выполнение 32 раундов сети Фейстеля")
        print("=" * 80)

        for i in range(32):
            round_key = self._round_keys[i]

            print(f"\n--- РАУНД {i+1:2d} ---")
            print(f"  Вход: L = 0x{left:08X}, R = 0x{right:08X}")
            print(f"  Ключ K{i+1}: 0x{round_key:08X}")

            # ШАГ a: вычисление функции g(R, K)
            print(f"\n  Шаг a: вычисление g(R, K)")

            # a1: сложение по модулю 2^32
            summed = (right + round_key) & 0xFFFFFFFF
            print(f"    a1) R + K = 0x{right:08X} + 0x{round_key:08X} = 0x{summed:08X}")

            # a2: нелинейное преобразование t (S-блоки)
            print(f"    a2) Нелинейное преобразование t (S-блоки):")
            transformed = self._t_transform_debug(summed)
            print(f"         Результат t = 0x{transformed:08X}")

            # a3: циклический сдвиг влево на 11 бит
            g_value = self._cyclic_left_shift_11(transformed)
            print(f"    a3) Циклический сдвиг на 11 бит влево: g = 0x{g_value:08X}")

            # ШАГ b: новая правая половина
            new_right = left ^ g_value
            print(f"\n  Шаг b: new_R = L XOR g")
            print(f"    0x{left:08X} XOR 0x{g_value:08X} = 0x{new_right:08X}")

            # ШАГ c: новая левая половина
            new_left = right
            print(f"\n  Шаг c: new_L = R = 0x{new_left:08X}")

            # Обновление для следующего раунда
            left, right = new_left, new_right

            print(f"\n  Выход раунда: L = 0x{left:08X}, R = 0x{right:08X}")

        # ШАГ 3: Финальная перестановка (R || L)
        print("\n" + "=" * 80)
        print("ШАГ 3: Финальная перестановка")
        print("=" * 80)
        print(f"  После 32 раундов: L = 0x{left:08X}, R = 0x{right:08X}")
        print(f"  Результат = R || L = 0x{right:08X}{left:08X}")

        result = self._halves_to_bytes(right, left)
        print(f"\n  Шифртекст (8 байт): {result.hex()}")

        return result

    def _t_transform_debug(self, value: int) -> int:
        """
        Нелинейное преобразование t с детальным выводом.
        По ГОСТ: t(a) = π₇(a₇) || π₆(a₆) || ... || π₀(a₀)
        где a₀ — младшие 4 бита, a₇ — старшие 4 бита.
        """
        print(f"      Разбиение 0x{value:08X} на 4-битные кусочки:")

        result = 0
        for i in range(8):
            nibble = (value >> (i * 4)) & 0x0F
            substituted = MagmaSBoxes.substitute(nibble, i)
            print(f"        Кусочек {i}: биты {i*4}-{i*4+3} = 0x{nibble:X} → S[{i}][{nibble}] = 0x{substituted:X}")
            result |= substituted << (i * 4)

        return result

    @staticmethod
    def _cyclic_left_shift_11(value: int) -> int:
        return ((value << 11) | (value >> 21)) & 0xFFFFFFFF


def debug_encrypt():
    """Отладка зашифрования на контрольном примере из ГОСТ."""
    print("\n" + "=" * 80)
    print("ОТЛАДКА ЗАШИФРОВАНИЯ (контрольный пример ГОСТ Р 34.12-2015)")
    print("=" * 80)

    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    master_key = bytes.fromhex(key_hex)

    plaintext_hex = "fedcba9876543210"
    plaintext = bytes.fromhex(plaintext_hex)

    expected_hex = "4ee901e5c2d8ca3d"
    expected = bytes.fromhex(expected_hex)

    print(f"\nИсходные данные:")
    print(f"  Ключ (256 бит): {key_hex}")
    print(f"  Открытый текст: {plaintext_hex}")
    print(f"  Ожидаемый шифр: {expected_hex}")

    # Вывод развернутых ключей
    print("\n" + "=" * 80)
    print("РАЗВЕРТЫВАНИЕ КЛЮЧА")
    print("=" * 80)

    k_parts = MagmaKeySchedule.split_into_8_parts(master_key)
    print("\nШаг 1: Разбиение ключа на 8 частей по 32 бита (K1...K8):")
    for i, k in enumerate(k_parts, 1):
        print(f"  K{i} = 0x{k:08X}")

    cipher = MagmaCipherDebug(master_key)

    print("\nШаг 2: Формирование 32 раундовых ключей:")
    for i, rk in enumerate(cipher._round_keys, 1):
        print(f"  K{i:2d} = 0x{rk:08X}")

    result = cipher.encrypt_block_debug(plaintext)

    print("\n" + "=" * 80)
    print("РЕЗУЛЬТАТ ПРОВЕРКИ")
    print("=" * 80)
    print(f"  Ожидаемый шифр: {expected_hex}")
    print(f"  Полученный шифр: {result.hex()}")

    if result == expected:
        print("\n✓ ОТЛАДКА ПРОЙДЕНА: результат соответствует ГОСТ!")
    else:
        print("\n✗ ОТЛАДКА НЕ ПРОЙДЕНА")

    return result == expected


def debug_decrypt():
    """Отладка расшифрования."""
    print("\n" + "=" * 80)
    print("ОТЛАДКА РАСШИФРОВАНИЯ (контрольный пример ГОСТ Р 34.12-2015)")
    print("=" * 80)

    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    master_key = bytes.fromhex(key_hex)

    ciphertext_hex = "4ee901e5c2d8ca3d"
    ciphertext = bytes.fromhex(ciphertext_hex)

    expected_hex = "fedcba9876543210"
    expected = bytes.fromhex(expected_hex)

    print(f"\nИсходные данные:")
    print(f"  Ключ: {key_hex}")
    print(f"  Шифртекст: {ciphertext_hex}")
    print(f"  Ожидаемый открытый текст: {expected_hex}")

    cipher = MagmaCipherDebug(master_key)
    result = cipher.decrypt_block(ciphertext)

    print(f"\nРезультат расшифрования: {result.hex()}")

    if result == expected:
        print("\n✓ ОТЛАДКА ПРОЙДЕНА")
    else:
        print("\n✗ ОТЛАДКА НЕ ПРОЙДЕНА")

    return result == expected


def main():
    """Главное меню."""
    while True:
        print("\n" + "=" * 80)
        print("ОТЛАДОЧНАЯ ВЕРСИЯ ШИФРА МАГМА")
        print("=" * 80)
        print("\nВыберите режим:")
        print("  1 - Отладка ЗАШИФРОВАНИЯ (контрольный пример из ГОСТ)")
        print("  2 - Отладка РАСШИФРОВАНИЯ")
        print("  q - Выход")

        choice = input("\nВаш выбор (1/2/q): ").strip().lower()

        if choice == '1':
            debug_encrypt()
            input("\nНажмите Enter для продолжения...")
        elif choice == '2':
            debug_decrypt()
            input("\nНажмите Enter для продолжения...")
        elif choice == 'q':
            print("\nВыход из программы. До свидания!")
            break
        else:
            print("\nНеверный выбор.")


if __name__ == "__main__":
    main()