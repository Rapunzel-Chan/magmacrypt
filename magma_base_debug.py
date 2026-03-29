"""
Отладочная версия шифра Магма с пошаговым выводом.
Для проверки промежуточных значений и сверки с ГОСТ.

Выбор режима:
1 - показать отладку ЗАШИФРОВАНИЯ (на контрольном примере ГОСТ)
2 - показать отладку РАСШИФРОВАНИЯ (на контрольном примере ГОСТ)
q - выход из программы
"""

import sys
from typing import Tuple

# Добавляем путь к модулям
sys.path.insert(0, '.')

from magma_code import MagmaCipher, MagmaSBoxes


class MagmaCipherDebug(MagmaCipher):
    """
    Отладочная версия шифра с выводом промежуточных значений.
    """

    def __init__(self, key: bytes, debug: bool = False):
        super().__init__(key)
        self.debug = debug

    # ========================================================================
    # ШИФРОВАНИЕ С ОТЛАДКОЙ
    # ========================================================================

    def encrypt_block_debug(self, plaintext: bytes) -> bytes:
        """Шифрование одного блока с отладочным выводом."""
        left, right = self._bytes_to_halves(plaintext)

        if self.debug:
            print("\n" + "=" * 70)
            print(f"НАЧАЛО ШИФРОВАНИЯ БЛОКА: {plaintext.hex()}")
            print(f"L0 = 0x{left:08X}, R0 = 0x{right:08X}")
            print("=" * 70)

        for i in range(32):
            round_key = self._round_keys[i]

            if self.debug:
                print(f"\n--- РАУНД {i + 1:2d} ---")
                print(f"  Вход: L = 0x{left:08X}, R = 0x{right:08X}")
                print(f"  Ключ K{i + 1}: 0x{round_key:08X}")

            # ШАГ a: g = (R + K) → S-блоки → сдвиг на 11
            summed = (right + round_key) & 0xFFFFFFFF
            if self.debug:
                print(f"  Шаг a1: R + K = 0x{right:08X} + 0x{round_key:08X} = 0x{summed:08X}")

            # Преобразование t (S-блоки)
            transformed = self._t_transform_debug(summed)
            if self.debug:
                print(f"  Шаг a2: После S-блоков (t) = 0x{transformed:08X}")

            # Циклический сдвиг
            g_value = self._cyclic_left_shift_11(transformed)
            if self.debug:
                print(f"  Шаг a3: После сдвига на 11 (g) = 0x{g_value:08X}")

            # ШАГ b: новая правая = L XOR g
            new_right = left ^ g_value
            if self.debug:
                print(f"  Шаг b: L XOR g = 0x{left:08X} XOR 0x{g_value:08X} = 0x{new_right:08X}")

            # ШАГ c: новая левая = R
            new_left = right
            if self.debug:
                print(f"  Шаг c: Новая L = R = 0x{new_left:08X}")
                print(f"  Выход раунда: L = 0x{new_left:08X}, R = 0x{new_right:08X}")

            left, right = new_left, new_right

        # Результат: R || L
        result = self._halves_to_bytes(right, left)

        if self.debug:
            print("\n" + "=" * 70)
            print(f"РЕЗУЛЬТАТ ПОСЛЕ 32 РАУНДОВ:")
            print(f"  L = 0x{left:08X}, R = 0x{right:08X}")
            print(f"  Блок (R||L): {result.hex()}")
            print("=" * 70)

        return result

    # ========================================================================
    # РАСШИФРОВАНИЕ С ОТЛАДКОЙ
    # ========================================================================

    def decrypt_block_debug(self, ciphertext: bytes) -> bytes:
        """Расшифрование одного блока с отладочным выводом."""
        left, right = self._bytes_to_halves(ciphertext)

        if self.debug:
            print("\n" + "=" * 70)
            print(f"НАЧАЛО РАСШИФРОВАНИЯ БЛОКА: {ciphertext.hex()}")
            print(f"L0 = 0x{left:08X}, R0 = 0x{right:08X}")
            print("=" * 70)

        # Расшифрование: ключи в обратном порядке
        for i in range(31, -1, -1):
            round_key = self._round_keys[i]
            round_num = i + 1

            if self.debug:
                print(f"\n--- РАУНД {round_num:2d} ---")
                print(f"  Вход: L = 0x{left:08X}, R = 0x{right:08X}")
                print(f"  Ключ K{round_num}: 0x{round_key:08X}")

            # ШАГ a: g = (R + K) → S-блоки → сдвиг на 11
            summed = (right + round_key) & 0xFFFFFFFF
            if self.debug:
                print(f"  Шаг a1: R + K = 0x{right:08X} + 0x{round_key:08X} = 0x{summed:08X}")

            # Преобразование t (S-блоки)
            transformed = self._t_transform_debug(summed)
            if self.debug:
                print(f"  Шаг a2: После S-блоков (t) = 0x{transformed:08X}")

            # Циклический сдвиг
            g_value = self._cyclic_left_shift_11(transformed)
            if self.debug:
                print(f"  Шаг a3: После сдвига на 11 (g) = 0x{g_value:08X}")

            # ШАГ b: новая правая = L XOR g
            new_right = left ^ g_value
            if self.debug:
                print(f"  Шаг b: L XOR g = 0x{left:08X} XOR 0x{g_value:08X} = 0x{new_right:08X}")

            # ШАГ c: новая левая = R
            new_left = right
            if self.debug:
                print(f"  Шаг c: Новая L = R = 0x{new_left:08X}")
                print(f"  Выход раунда: L = 0x{new_left:08X}, R = 0x{new_right:08X}")

            left, right = new_left, new_right

        # Результат: R || L
        result = self._halves_to_bytes(right, left)

        if self.debug:
            print("\n" + "=" * 70)
            print(f"РЕЗУЛЬТАТ ПОСЛЕ 32 РАУНДОВ:")
            print(f"  L = 0x{left:08X}, R = 0x{right:08X}")
            print(f"  Блок (R||L): {result.hex()}")
            print("=" * 70)

        return result

    # ========================================================================
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # ========================================================================

    def _t_transform_debug(self, value: int) -> int:
        """Преобразование t с детальным выводом."""
        if self.debug:
            print(f"    Разбиение на кусочки (младшие→старшие):")

        result = 0
        for i in range(8):
            nibble = (value >> (i * 4)) & 0x0F
            substituted = MagmaSBoxes.substitute(nibble, i)
            result |= substituted << (i * 4)

            if self.debug:
                print(f"      Кусочек {i}: 0x{nibble:X} → S[{i}][{nibble}] = 0x{substituted:X}")

        if self.debug:
            print(f"    Результат t: 0x{result:08X}")

        return result

    @staticmethod
    def _cyclic_left_shift_11(value: int) -> int:
        return ((value << 11) | (value >> 21)) & 0xFFFFFFFF

    def _bytes_to_halves(self, block: bytes) -> Tuple[int, int]:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Блок должен быть {self.BLOCK_SIZE} байт")
        left = int.from_bytes(block[0:4], byteorder='big')
        right = int.from_bytes(block[4:8], byteorder='big')
        return left, right

    def _halves_to_bytes(self, left: int, right: int) -> bytes:
        return left.to_bytes(4, 'big') + right.to_bytes(4, 'big')


# ============================================================================
# ЗАПУСК ОТЛАДКИ
# ============================================================================

def debug_encrypt():
    """Отладка шифрования на контрольном примере ГОСТ."""
    print("\n" + "=" * 70)
    print("ОТЛАДКА ШИФРОВАНИЯ (контрольный пример ГОСТ)")
    print("=" * 70)

    # Ключ из ГОСТ
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    key = bytes.fromhex(key_hex)

    # Открытый текст из ГОСТ
    plaintext_hex = "fedcba9876543210"
    plaintext = bytes.fromhex(plaintext_hex)

    # Ожидаемый шифротекст
    expected_hex = "4ee901e5c2d8ca3d"
    expected = bytes.fromhex(expected_hex)

    print(f"\nКлюч:           {key_hex}")
    print(f"Открытый текст: {plaintext_hex}")
    print(f"Ожидаемый шифр: {expected_hex}")

    # Создаем отладочный шифр
    cipher = MagmaCipherDebug(key, debug=True)

    # Шифруем с выводом
    ciphertext = cipher.encrypt_block_debug(plaintext)

    print(f"\n{'=' * 70}")
    print(f"ИТОГОВЫЙ ШИФРОТЕКСТ: {ciphertext.hex()}")
    print(f"ОЖИДАЛОСЬ:           {expected_hex}")
    print(f"{'=' * 70}")

    if ciphertext == expected:
        print("\n✓ ОТЛАДКА ШИФРОВАНИЯ ПРОЙДЕНА!")
    else:
        print("\n✗ ОТЛАДКА ШИФРОВАНИЯ: ЕСТЬ РАСХОЖДЕНИЯ!")


def debug_decrypt():
    """Отладка расшифрования на контрольном примере ГОСТ."""
    print("\n" + "=" * 70)
    print("ОТЛАДКА РАСШИФРОВАНИЯ (контрольный пример ГОСТ)")
    print("=" * 70)

    # Ключ из ГОСТ
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    key = bytes.fromhex(key_hex)

    # Шифротекст из ГОСТ (результат шифрования)
    ciphertext_hex = "4ee901e5c2d8ca3d"
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Ожидаемый открытый текст
    expected_hex = "fedcba9876543210"
    expected = bytes.fromhex(expected_hex)

    print(f"\nКлюч:           {key_hex}")
    print(f"Шифротекст:     {ciphertext_hex}")
    print(f"Ожидаемый текст: {expected_hex}")

    # Создаем отладочный шифр
    cipher = MagmaCipherDebug(key, debug=True)

    # Расшифровываем с выводом
    plaintext = cipher.decrypt_block_debug(ciphertext)

    print(f"\n{'=' * 70}")
    print(f"ИТОГОВЫЙ РАСШИФРОВАННЫЙ ТЕКСТ: {plaintext.hex()}")
    print(f"ОЖИДАЛОСЬ:                      {expected_hex}")
    print(f"{'=' * 70}")

    if plaintext == expected:
        print("\n✓ ОТЛАДКА РАСШИФРОВАНИЯ ПРОЙДЕНА!")
    else:
        print("\n✗ ОТЛАДКА РАСШИФРОВАНИЯ: ЕСТЬ РАСХОЖДЕНИЯ!")


# ============================================================================
# ГЛАВНОЕ МЕНЮ С ЦИКЛОМ
# ============================================================================

def main():
    """Главное меню с циклом."""
    while True:
        print("\n" + "=" * 70)
        print("ОТЛАДОЧНАЯ ВЕРСИЯ ШИФРА МАГМА")
        print("=" * 70)
        print("\nВыберите режим отладки:")
        print("  1 - Отладка ЗАШИФРОВАНИЯ (на примере ГОСТ)")
        print("  2 - Отладка РАСШИФРОВАНИЯ (на примере ГОСТ)")
        print("  q - Выход из программы")

        choice = input("\nВаш выбор (1/2/q): ").strip().lower()

        if choice == '1':
            debug_encrypt()
            input("\nНажмите Enter, чтобы продолжить...")
        elif choice == '2':
            debug_decrypt()
            input("\nНажмите Enter, чтобы продолжить...")
        elif choice == 'q':
            print("\nВыход из программы. До свидания!")
            break
        else:
            print("\nОшибка: неверный выбор. Пожалуйста, введите 1, 2 или q.")
            input("Нажмите Enter, чтобы продолжить...")


# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    main()