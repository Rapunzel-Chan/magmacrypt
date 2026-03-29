"""
ГОСТ Р 34.12-2015. Блочный шифр "Магма" (Magma)
Длина блока: 64 бита (8 байт)
Длина ключа: 256 бит (32 байта)
Число раундов: 32
Структура: сеть Фейстеля

ПОШАГОВЫЙ АЛГОРИТМ:
1. Получить ключ (32 байта)
2. Разделить на 8 частей K1...K8 (по 4 байта)
3. Сформировать 32 раундовых ключа по порядку из ГОСТ
4. Взять блок данных (8 байт), разделить на L и R (по 4 байта)
5. Для каждого раунда i = 1..32:
   a) g = ((R + Ki) mod 2^32) → S-блоки → циклический сдвиг на 11
   b) new_R = L XOR g
   c) new_L = R
   d) L = new_L, R = new_R
6. Результат = R || L (правая + левая)
"""

import os
from typing import List, Tuple


# ============================================================================
# ШАГ 1: S-БЛОКИ (фиксированные таблицы замен)
# ============================================================================

class MagmaSBoxes:
    """
    Фиксированные S-блоки из ГОСТ Р 34.12-2015.
    Каждый S-блок: 4 бита на входе -> 4 бита на выходе.
    """

    _S_BOXES = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
    ]

    @classmethod
    def substitute(cls, value: int, box_index: int) -> int:
        """Замена 4-битного значения по указанному S-блоку."""
        return cls._S_BOXES[box_index][value & 0x0F]


# ============================================================================
# ШАГ 2-3: РАЗВЕРТЫВАНИЕ КЛЮЧА
# ============================================================================

class MagmaKeySchedule:
    """
    Развертывание ключа для шифра Магма.
    ШАГ 2: 32 байта → 8 частей по 32 бита (K1...K8)
    ШАГ 3: 8 частей → 32 раундовых ключа с учетом порядка из ГОСТ
    """

    @staticmethod
    def split_into_8_parts(key: bytes) -> List[int]:
        """
        ШАГ 2: Разбивает 32-байтный ключ на 8 частей по 4 байта (32 бита).
        Возвращает список из 8 целых чисел K1...K8.
        """
        if len(key) != 32:
            raise ValueError("Ключ должен быть 32 байта (256 бит)")

        parts = []
        for i in range(8):
            chunk = key[i * 4:(i + 1) * 4]
            value = int.from_bytes(chunk, byteorder='big')
            parts.append(value)
        return parts

    @staticmethod
    def generate_round_keys(master_key: bytes) -> List[int]:
        """
        ШАГ 3: Из мастер-ключа получаем 32 раундовых ключа.
        """
        # ШАГ 2: разбиваем на 8 частей
        k = MagmaKeySchedule.split_into_8_parts(master_key)

        # Порядок использования ключей в 32 раундах (по ГОСТ Р 34.12-2015)
        order = [
            0, 1, 2, 3, 4, 5, 6, 7,  # раунды 1-8
            0, 1, 2, 3, 4, 5, 6, 7,  # раунды 9-16
            0, 1, 2, 3, 4, 5, 6, 7,  # раунды 17-24
            7, 6, 5, 4, 3, 2, 1, 0   # раунды 25-32 (обратный порядок)
        ]

        round_keys = [k[idx] for idx in order]
        return round_keys


# ============================================================================
# ШАГ 5: ФУНКЦИЯ g (СЕТЬ ФЕЙСТЕЛЯ)
# ============================================================================

class MagmaFeistelFunction:
    """
    Функция g(R, K) — основа сети Фейстеля.
    Выполняет:
    1. Сложение R + K по модулю 2^32
    2. Нелинейное преобразование t (S-блоки)
    3. Циклический сдвиг влево на 11 бит
    """

    @staticmethod
    def _cyclic_left_shift_11(value: int) -> int:
        """Циклический сдвиг 32-битного числа влево на 11 бит."""
        return ((value << 11) | (value >> 21)) & 0xFFFFFFFF

    @classmethod
    def _t_transform(cls, value: int) -> int:
        """
        Нелинейное преобразование t:
        Разбиваем 32-битное число на 8 кусочков по 4 бита,
        каждый заменяем через свой S-блок, собираем обратно.
        """
        result = 0
        for i in range(8):
            # Извлекаем i-й кусочек (младшие биты = i=0)
            nibble = (value >> (i * 4)) & 0x0F
            # Заменяем через S-блок
            substituted = MagmaSBoxes.substitute(nibble, i)
            # Помещаем обратно
            result |= substituted << (i * 4)
        return result

    @classmethod
    def g(cls, right: int, round_key: int) -> int:
        """
        Функция g(R, K):
        Шаг a: (R + K) mod 2^32
        Шаг b: нелинейное преобразование t (S-блоки)
        Шаг c: циклический сдвиг влево на 11 бит
        """
        # Шаг a: сложение
        summed = (right + round_key) & 0xFFFFFFFF
        # Шаг b: S-блоки
        transformed = cls._t_transform(summed)
        # Шаг c: сдвиг
        result = cls._cyclic_left_shift_11(transformed)
        return result


# ============================================================================
# ШАГ 4, 5, 6: ОСНОВНОЙ КЛАСС ШИФРА
# ============================================================================

class MagmaCipher:
    """
    ШАГ 4: Взять блок данных (8 байт), разделить на L и R
    ШАГ 5: Выполнить 32 раунда сети Фейстеля
    ШАГ 6: Результат = R || L (правая + левая, НЕ МЕНЯЕМ МЕСТАМИ)
    """

    BLOCK_SIZE = 8  # 64 бита

    def __init__(self, key: bytes):
        """Инициализация шифра с 32-байтным ключом."""
        if len(key) != 32:
            raise ValueError(f"Ключ должен быть 32 байта, получено {len(key)}")
        self._round_keys = MagmaKeySchedule.generate_round_keys(key)

    def _bytes_to_halves(self, block: bytes) -> Tuple[int, int]:
        """Разделяем 8-байтный блок на левую и правую половины (по 4 байта)."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Блок должен быть {self.BLOCK_SIZE} байт")
        left = int.from_bytes(block[0:4], byteorder='big')
        right = int.from_bytes(block[4:8], byteorder='big')
        return left, right

    def _halves_to_bytes(self, left: int, right: int) -> bytes:
        """Собираем левую и правую половины в 8-байтный блок."""
        return left.to_bytes(4, 'big') + right.to_bytes(4, 'big')

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Шифрование одного 8-байтного блока.

        ПОШАГОВО:
        1. Разделить блок на L и R
        2. Для каждого раунда i = 1..32:
           a) g = MagmaFeistelFunction.g(R, round_key[i])
           b) new_R = L XOR g
           c) new_L = R
           d) L = new_L, R = new_R
        3. Результат = R || L
        """
        # ШАГ 1: разделяем
        left, right = self._bytes_to_halves(plaintext)

        # ШАГ 2: 32 раунда
        for i in range(32):
            # Шаг a: вычисляем g(R, Ki)
            g_value = MagmaFeistelFunction.g(right, self._round_keys[i])
            # Шаг b: новая правая = L XOR g
            new_right = left ^ g_value
            # Шаг c: новая левая = R
            new_left = right
            # Шаг d: обновляем
            left, right = new_left, new_right

        # ШАГ 3: результат = правая + левая (НЕ МЕНЯЕМ МЕСТАМИ!)
        return self._halves_to_bytes(right, left)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """
        Расшифрование одного 8-байтного блока.
        В сети Фейстеля расшифрование использует те же операции,
        но ключи подаются в обратном порядке.
        """
        left, right = self._bytes_to_halves(ciphertext)

        # Ключи в обратном порядке (с 32-го по 1-й)
        for i in range(31, -1, -1):
            g_value = MagmaFeistelFunction.g(right, self._round_keys[i])
            new_right = left ^ g_value
            new_left = right
            left, right = new_left, new_right

        return self._halves_to_bytes(right, left)

    def encrypt(self, data: bytes) -> bytes:
        """Шифрование данных произвольной длины (с PKCS#7 паддингом)."""
        # Добавляем паддинг
        padding_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        if padding_len == 0:
            padding_len = self.BLOCK_SIZE
        padded = data + bytes([padding_len] * padding_len)

        # Шифруем блоками
        result = bytearray()
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            result.extend(self.encrypt_block(block))
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифрование данных произвольной длины (с удалением паддинга)."""
        if len(data) % self.BLOCK_SIZE != 0:
            raise ValueError("Данные должны быть кратны размеру блока")

        # Расшифровываем блоками
        result = bytearray()
        for i in range(0, len(data), self.BLOCK_SIZE):
            block = data[i:i + self.BLOCK_SIZE]
            result.extend(self.decrypt_block(block))

        # Удаляем паддинг
        padding_len = result[-1]
        if padding_len > self.BLOCK_SIZE or padding_len == 0:
            raise ValueError("Неверный паддинг")
        if result[-padding_len:] != bytes([padding_len]) * padding_len:
            raise ValueError("Неверный паддинг")
        return bytes(result[:-padding_len])


# ============================================================================
# ТЕСТИРОВАНИЕ НА КОНТРОЛЬНЫХ ПРИМЕРАХ ИЗ ГОСТ
# ============================================================================

def test_magma():
    """Проверка на контрольных примерах из ГОСТ Р 34.12-2015 (Приложение А.2)."""
    print("=" * 70)
    print("ТЕСТИРОВАНИЕ ШИФРА МАГМА НА КОНТРОЛЬНЫХ ПРИМЕРАХ ИЗ ГОСТ")
    print("=" * 70)

    # Ключ из ГОСТ (32 байта)
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    master_key = bytes.fromhex(key_hex)

    # Открытый текст из ГОСТ
    plaintext_hex = "fedcba9876543210"
    plaintext = bytes.fromhex(plaintext_hex)

    # Ожидаемый шифротекст из ГОСТ
    expected_hex = "4ee901e5c2d8ca3d"
    expected = bytes.fromhex(expected_hex)

    print(f"\nКлюч:           {key_hex}")
    print(f"Открытый текст: {plaintext_hex}")
    print(f"Ожидаемый шифр: {expected_hex}")

    # Шифруем
    cipher = MagmaCipher(master_key)
    ciphertext = cipher.encrypt_block(plaintext)
    ciphertext_hex = ciphertext.hex()

    print(f"\nПолученный шифр: {ciphertext_hex}")

    if ciphertext == expected:
        print("\n✓ ШИФРОВАНИЕ: УСПЕШНО!")
    else:
        print("\n✗ ШИФРОВАНИЕ: ОШИБКА!")

    # Расшифровываем
    decrypted = cipher.decrypt_block(ciphertext)
    decrypted_hex = decrypted.hex()

    print(f"Расшифрованный: {decrypted_hex}")

    if decrypted == plaintext:
        print("✓ РАСШИФРОВАНИЕ: УСПЕШНО!")
    else:
        print("✗ РАСШИФРОВАНИЕ: ОШИБКА!")

    return ciphertext == expected and decrypted == plaintext


# ============================================================================
# ИНТЕРАКТИВНЫЙ РЕЖИМ
# ============================================================================
def interactive_mode():
    """Интерактивный режим с циклом для повторных попыток."""
    print("\n" + "=" * 70)
    print("ИНТЕРАКТИВНЫЙ РЕЖИМ РАБОТЫ")
    print("=" * 70)

    while True:  # <-- ДОБАВЛЕН ЦИКЛ
        try:
            print("\n--- НОВАЯ ОПЕРАЦИЯ ---")

            # 1. Ввод ключа
            print("\n[1] Введите секретный ключ (или 'q' для выхода)")
            key_input = input("Ключ: ").strip()
            # key_input = input("Ключ (64 hex-символа): ").strip().replace(" ", "")

            # if key_input.lower() == 'q':
            #     print("Выход из программы.")
            #     break
            key_input = ''.join(key_input.split())  # удаляем все пробелы и табуляции
            key_input = key_input.replace('\n', '').replace('\r', '').replace('\t', '')

            if key_input.lower() == 'q':
                print("Выход из программы.")
                break

            # Проверяем длину
            if len(key_input) != 64:
                print(f"Ошибка: ключ должен быть 64 hex-символа, получено {len(key_input)}")
                print(f"Введено: {key_input}")
                continue

            # Проверяем, что все символы допустимы
            valid_chars = set('0123456789abcdefABCDEF')
            invalid_chars = [c for c in key_input if c not in valid_chars]
            if invalid_chars:
                print(f"Ошибка: найдены недопустимые символы: {invalid_chars}")
                print("Допустимы только: 0-9, A-F, a-f")
                continue

            try:
                key = bytes.fromhex(key_input)
                if len(key) != 32:
                    print(f"Ошибка: ключ должен быть 32 байта, получено {len(key)}")
                    continue  # <-- возвращаемся к началу цикла
                print(f"✓ Ключ принят")
                print(f"  Hex: {key.hex()}")
            except ValueError as e:
                print(f"Ошибка преобразования hex: {e}")
                continue

            # 2. Выбор действия
            print("\n[2] Выберите действие")
            print("    1 - Зашифровать файл")
            print("    2 - Расшифровать файл")
            print("    0 - Новый ключ / начать заново")

            action = input("\nДействие (0-2): ").strip()

            if action == '0':
                continue
            if action not in ['1', '2']:
                print("Ошибка: выберите 1, 2 или 0")
                continue

            encrypt = (action == '1')

            # 3. Путь к входному файлу
            print(f"\n[3] Введите путь к файлу")
            input_path = input("Путь: ").strip()

            if not os.path.exists(input_path):
                print(f"Ошибка: файл '{input_path}' не найден")
                continue

            # 4. Путь к выходному файлу
            default_output = input_path + (".enc" if encrypt else ".dec")
            print(f"\n[4] Выходной файл (Enter = {default_output})")
            output_path = input("Путь: ").strip()
            if not output_path:
                output_path = default_output

            # 5. Выполнение
            print("\n⏳ Выполняется...")
            cipher = MagmaCipher(key)

            with open(input_path, 'rb') as f:
                data = f.read()

            try:
                if encrypt:
                    result = cipher.encrypt(data)
                else:
                    result = cipher.decrypt(data)

                with open(output_path, 'wb') as f:
                    f.write(result)

                print(f"\n✓ ГОТОВО! Результат: {output_path}")

            except Exception as e:
                print(f"\n✗ ОШИБКА: {e}")
                print("  Возможно, ключ неверный или файл поврежден.")
                continue

            # 6. Спросить, продолжить ли
            again = input("\nВыполнить еще одну операцию? (y/n): ").strip().lower()
            if again != 'y':
                print("Выход из программы.")
                break

        except KeyboardInterrupt:
            print("\n\nПрервано пользователем.")
            break
        except Exception as e:
            print(f"\nНепредвиденная ошибка: {e}")
            continue


class MagmaCipherDebug(MagmaCipher):
    """
    Отладочная версия шифра с выводом промежуточных значений.
    Для использования: cipher = MagmaCipherDebug(key, debug=True)
    """

    def __init__(self, key: bytes, debug: bool = False):
        super().__init__(key)
        self.debug = debug

    def encrypt_block_debug(self, plaintext: bytes) -> bytes:
        """Шифрование с отладочным выводом."""
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
            transformed = self._t_transform(summed)
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

    def _t_transform(self, value: int) -> int:
        """Преобразование t с детальным выводом (для отладки)."""
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


# ============================================================================
# ФУНКЦИЯ ДЛЯ ОТЛАДОЧНОГО ТЕСТА
# ============================================================================

def debug_test():
    """Отладочный тест с выводом всех промежуточных значений."""
    print("=" * 70)
    print("ОТЛАДОЧНЫЙ ТЕСТ С ПОШАГОВЫМ ВЫВОДОМ")
    print("=" * 70)

    # Ключ из ГОСТ
    key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    key = bytes.fromhex(key_hex)

    # Открытый текст из ГОСТ
    plaintext_hex = "fedcba9876543210"
    plaintext = bytes.fromhex(plaintext_hex)

    print(f"\nКлюч:           {key_hex}")
    print(f"Открытый текст: {plaintext_hex}")
    print(f"Ожидаемый шифр: 4ee901e5c2d8ca3d")

    # Создаем отладочный шифр
    cipher = MagmaCipherDebug(key, debug=True)

    # Шифруем с выводом
    ciphertext = cipher.encrypt_block_debug(plaintext)

    print(f"\n{'=' * 70}")
    print(f"ИТОГОВЫЙ ШИФРОТЕКСТ: {ciphertext.hex()}")
    print(f"ОЖИДАЛОСЬ:           4ee901e5c2d8ca3d")
    print(f"{'=' * 70}")

    if ciphertext.hex() == "4ee901e5c2d8ca3d":
        print("\n✓ ОТЛАДКА ПРОЙДЕНА! Все шаги корректны.")
    else:
        print("\n✗ ОТЛАДКА: ЕСТЬ РАСХОЖДЕНИЯ!")


# ============================================================================
# ЗАПУСК С ОТЛАДКОЙ
# ============================================================================

if __name__ == "__main__":
    # Запуск отладочного теста
    debug_test()

    # Затем обычное тестирование
    test_magma()

    # Интерактивный режим
    run_interactive = input("\nЗапустить интерактивный режим? (y/n): ").strip().lower()
    if run_interactive == 'y':
        interactive_mode()


# def interactive_mode():
#     """Интерактивный режим: шифрование/расшифрование файлов."""
#     print("\n" + "=" * 70)
#     print("ИНТЕРАКТИВНЫЙ РЕЖИМ РАБОТЫ")
#     print("=" * 70)
#
#     try:
#         # 1. Ввод ключа
#         print("\n[1] Введите секретный ключ")
#         print("    Ключ должен быть 32 байта (256 бит) в шестнадцатеричном виде")
#         print("    Пример: ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
#         key_input = input("\nКлюч (64 hex-символа): ").strip().replace(" ", "")
#
#         try:
#             key = bytes.fromhex(key_input)
#             if len(key) != 32:
#                 print(f"Ошибка: ключ должен быть 32 байта, получено {len(key)}")
#                 return
#             print(f"✓ Ключ принят ({len(key)} байт)")
#         except ValueError:
#             print("Ошибка: ключ должен быть в hex-формате (0-9, A-F)")
#             return
#
#         # 2. Выбор действия
#         print("\n[2] Выберите действие")
#         print("    1 - Зашифровать файл")
#         print("    2 - Расшифровать файл")
#
#         action = input("\nДействие (1-2): ").strip()
#
#         if action not in ['1', '2']:
#             print("Ошибка: выберите 1 или 2")
#             return
#
#         encrypt = (action == '1')
#         action_text = "зашифрования" if encrypt else "расшифрования"
#
#         # 3. Путь к входному файлу
#         print(f"\n[3] Выберите файл для {action_text}")
#         print("    Укажите путь к файлу. Примеры:")
#         print("    - test.txt (если файл в текущей папке)")
#         print("    - folder/test.txt (если в подпапке)")
#         print("    - C:/Users/name/test.txt (полный путь)")
#
#         input_path = input("\nПуть к файлу: ").strip()
#
#         if not os.path.exists(input_path):
#             print(f"Ошибка: файл '{input_path}' не найден")
#             print(f"Текущая папка: {os.getcwd()}")
#             return
#
#         file_size = os.path.getsize(input_path)
#         print(f"✓ Файл найден. Размер: {file_size} байт")
#
#         # 4. Путь к выходному файлу
#         default_output = input_path + (".enc" if encrypt else ".dec")
#         print(f"\n[4] Сохранение результата")
#         print(f"    Предлагаемое имя: {default_output}")
#         output_path = input("Путь для сохранения (Enter для предложенного): ").strip()
#
#         if not output_path:
#             output_path = default_output
#
#         # Создаем папку для выходного файла, если нужно
#         output_dir = os.path.dirname(output_path)
#         if output_dir and not os.path.exists(output_dir):
#             os.makedirs(output_dir)
#             print(f"  Создана папка: {output_dir}")
#
#         # 5. Подтверждение
#         print("\n" + "-" * 50)
#         print("ПАРАМЕТРЫ ОПЕРАЦИИ:")
#         print(f"  Операция: {'ЗАШИФРОВАНИЕ' if encrypt else 'РАСШИФРОВАНИЕ'}")
#         print(f"  Входной файл: {input_path} ({file_size} байт)")
#         print(f"  Выходной файл: {output_path}")
#         print("-" * 50)
#
#         confirm = input("\nВыполнить операцию? (y/n): ").strip().lower()
#         if confirm != 'y':
#             print("Операция отменена")
#             return
#
#         # 6. Выполнение
#         print("\n⏳ Выполняется операция...")
#
#         cipher = MagmaCipher(key)
#
#         with open(input_path, 'rb') as f:
#             data = f.read()
#
#         if encrypt:
#             result = cipher.encrypt(data)
#         else:
#             result = cipher.decrypt(data)
#
#         with open(output_path, 'wb') as f:
#             f.write(result)
#
#         print(f"\n✓ ГОТОВО! Результат сохранен в {output_path}")
#         print(f"  Размер результата: {len(result)} байт")
#
#     except Exception as e:
#         print(f"\nОшибка: {e}")


# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    # Запуск теста ГОСТ
    test_passed = test_magma()

    # Запрос на запуск интерактивного режима
    print("\n" + "=" * 70)
    run_interactive = input("Запустить интерактивный режим для работы с файлами? (y/n): ").strip().lower()
    if run_interactive == 'y':
        interactive_mode()

# """
# ГОСТ Р 34.12-2015. Блочный шифр "Магма" (Magma)
# Длина блока: 64 бита (8 байт)
# Длина ключа: 256 бит (32 байта)
# Число раундов: 32
# Структура: сеть Фейстеля
#
# Реализация без использования сторонних библиотек шифрования.
# """
#
# import os
# import struct
# from typing import Tuple, List, Union
#
#
# class MagmaSBoxes:
#     """
#     Фиксированные S-блоки (таблицы замен) из ГОСТ Р 34.12-2015.
#     Каждый S-блок: 4 бита на входе -> 4 бита на выходе.
#     """
#
#     # Таблицы замен (8 блоков по 16 значений)
#     _S_BOXES = [
#         [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
#         [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
#         [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
#         [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
#         [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
#         [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
#         [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
#         [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
#     ]
#
#     @classmethod
#     def substitute(cls, value: int, box_index: int) -> int:
#         """
#         Замена 4-битного значения по указанному S-блоку.
#
#         Args:
#             value: 4-битное значение (0-15)
#             box_index: индекс S-блока (0-7)
#
#         Returns:
#             Замененное 4-битное значение
#         """
#         return cls._S_BOXES[box_index][value & 0x0F]
#
#
# class MagmaKeySchedule:
#     """
#     Развертывание ключа для шифра Магма.
#     Из 256-битного ключа (32 байта) получаем 32 раундовых ключа по 32 бита.
#     """
#
#     @staticmethod
#     def _split_key(key: bytes) -> List[int]:
#         """
#         Разбивает 32-байтный ключ на 8 частей по 4 байта (32 бита).
#
#         Args:
#             key: 32 байта
#
#         Returns:
#             Список из 8 целых чисел (раундовые ключи K1...K8)
#         """
#         if len(key) != 32:
#             raise ValueError("Ключ должен быть 32 байта (256 бит)")
#
#         round_keys = []
#         for i in range(8):
#             # Берем 4 байта, начиная с позиции i*4
#             chunk = key[i * 4:(i + 1) * 4]
#             # Преобразуем в 32-битное целое (big-endian, как в спецификации)
#             value = int.from_bytes(chunk, byteorder='big')
#             round_keys.append(value)
#
#         return round_keys
#
#     @staticmethod
#     def _cyclic_left_shift_11(value: int) -> int:
#         """
#         Циклический сдвиг 32-битного числа влево на 11 бит.
#
#         Args:
#             value: 32-битное число
#
#         Returns:
#             Результат циклического сдвига
#         """
#         return ((value << 11) | (value >> 21)) & 0xFFFFFFFF
#
#     @classmethod
#     def _t_transform(cls, value: int) -> int:
#         """
#         Преобразование t: замена байтов через S-блоки.
#         Вход: 32-битное число.
#         Выход: 32-битное число после замены всех 4-битных кусочков.
#
#         Число разбивается на 8 кусочков по 4 бита.
#         Кусочек 0 (младшие 4 бита) заменяется по S[0],
#         кусочек 1 — по S[1], и т.д. до кусочка 7 (старшие 4 бита).
#         """
#         result = 0
#         for i in range(8):
#             # Извлекаем i-й кусочек (4 бита) от младших к старшим
#             nibble = (value >> (i * 4)) & 0x0F
#             # Заменяем через S-блок
#             substituted = MagmaSBoxes.substitute(nibble, i)
#             # Помещаем обратно на ту же позицию
#             result |= substituted << (i * 4)
#         return result
#
#     @classmethod
#     def _g_function(cls, part: int, key: int) -> int:
#         """
#         Функция g (основная функция раунда).
#
#         Args:
#             part: правая половина блока (32 бита)
#             key: раундовый ключ (32 бита)
#
#         Returns:
#             32-битный результат после преобразования
#         """
#         # Шаг 1: сложение по модулю 2^32
#         summed = (part + key) & 0xFFFFFFFF
#         # Шаг 2: преобразование t (замена через S-блоки)
#         transformed = cls._t_transform(summed)
#         # Шаг 3: циклический сдвиг влево на 11 бит
#         result = cls._cyclic_left_shift_11(transformed)
#         return result
#
#     @classmethod
#     def generate_round_keys(cls, master_key: bytes) -> List[int]:
#         """
#         Генерация 32 раундовых ключей из мастер-ключа.
#
#         Args:
#             master_key: 32 байта (256 бит)
#
#         Returns:
#             Список из 32 целых чисел (раундовые ключи)
#         """
#         # Разбиваем ключ на 8 частей
#         k = cls._split_key(master_key)
#
#         # Порядок использования ключей в 32 раундах (по ГОСТ Р 34.12-2015)
#         order = [
#             0, 1, 2, 3, 4, 5, 6, 7,  # раунды 1-8
#             0, 1, 2, 3, 4, 5, 6, 7,  # раунды 9-16
#             0, 1, 2, 3, 4, 5, 6, 7,  # раунды 17-24
#             7, 6, 5, 4, 3, 2, 1, 0   # раунды 25-32 (обратный порядок)
#         ]
#
#         round_keys = [k[idx] for idx in order]
#         return round_keys
#
#
# class MagmaRound:
#     """
#     Один раунд шифрования/расшифрования.
#     """
#
#     @staticmethod
#     def round_function(round_key: int, right: int) -> int:
#         """
#         Функция F(R, K) для одного раунда.
#         """
#         return MagmaKeySchedule._g_function(right, round_key)
#
#     @classmethod
#     def encrypt_round(cls, left: int, right: int, round_key: int) -> Tuple[int, int]:
#         """
#         Один раунд шифрования.
#
#         Args:
#             left: левая половина (32 бита)
#             right: правая половина (32 бита)
#             round_key: раундовый ключ (32 бита)
#
#         Returns:
#             (новая левая, новая правая)
#         """
#         new_left = right
#         new_right = left ^ cls.round_function(round_key, right)
#         return new_left, new_right
#
#     @classmethod
#     def decrypt_round(cls, left: int, right: int, round_key: int) -> Tuple[int, int]:
#         """
#         Один раунд расшифрования.
#         В сети Фейстеля расшифрование использует те же операции,
#         но ключи подаются в обратном порядке.
#         """
#         new_left = right
#         new_right = left ^ cls.round_function(round_key, right)
#         return new_left, new_right
#
#
# class MagmaCipher:
#     """
#     Основной класс шифра Магма.
#     Реализует шифрование и расшифрование блока 64 бит.
#     """
#
#     def __init__(self, key: bytes):
#         """
#         Инициализация шифра с заданным ключом.
#
#         Args:
#             key: 32 байта (256 бит)
#         """
#         if len(key) != 32:
#             raise ValueError(f"Ключ должен быть 32 байта, получено {len(key)} байт")
#
#         self._master_key = key
#         self._round_keys = MagmaKeySchedule.generate_round_keys(key)
#
#     def _bytes_to_halves(self, block: bytes) -> Tuple[int, int]:
#         """
#         Преобразует 8-байтный блок в две 32-битные половины.
#
#         Args:
#             block: 8 байт
#
#         Returns:
#             (левая половина, правая половина)
#         """
#         if len(block) != 8:
#             raise ValueError(f"Блок должен быть 8 байт, получено {len(block)} байт")
#
#         left = int.from_bytes(block[0:4], byteorder='big')
#         right = int.from_bytes(block[4:8], byteorder='big')
#         return left, right
#
#     def _halves_to_bytes(self, left: int, right: int) -> bytes:
#         """
#         Преобразует две 32-битные половины в 8-байтный блок.
#         """
#         return left.to_bytes(4, byteorder='big') + right.to_bytes(4, byteorder='big')
#
#     def encrypt_block(self, plaintext: bytes) -> bytes:
#         """
#         Шифрование одного 8-байтного блока.
#
#         Args:
#             plaintext: 8 байт открытого текста
#
#         Returns:
#             8 байт шифротекста
#         """
#         left, right = self._bytes_to_halves(plaintext)
#
#         # 32 раунда шифрования
#         for i in range(32):
#             left, right = MagmaRound.encrypt_round(left, right, self._round_keys[i])
#
#         # После 32 раундов половинки меняются местами
#         return self._halves_to_bytes(right, left)
#
#     def decrypt_block(self, ciphertext: bytes) -> bytes:
#         """
#         Расшифрование одного 8-байтного блока.
#
#         Args:
#             ciphertext: 8 байт шифротекста
#
#         Returns:
#             8 байт открытого текста
#         """
#         left, right = self._bytes_to_halves(ciphertext)
#
#         # Расшифрование: ключи в обратном порядке
#         for i in range(31, -1, -1):
#             left, right = MagmaRound.decrypt_round(left, right, self._round_keys[i])
#
#         # После 32 раундов половинки меняются местами
#         return self._halves_to_bytes(right, left)
#
#     def encrypt(self, data: bytes, padding: bool = True) -> bytes:
#         """
#         Шифрование данных произвольной длины (с паддингом).
#
#         Args:
#             data: произвольные байты
#             padding: добавлять ли PKCS#7 паддинг
#
#         Returns:
#             Зашифрованные данные (длина кратна 8 байтам)
#         """
#         # Добавляем паддинг если нужно
#         if padding:
#             data = self._add_pkcs7_padding(data)
#
#         # Шифруем блоками по 8 байт
#         result = bytearray()
#         for i in range(0, len(data), 8):
#             block = data[i:i+8]
#             encrypted = self.encrypt_block(block)
#             result.extend(encrypted)
#
#         return bytes(result)
#
#     def decrypt(self, data: bytes, padding: bool = True) -> bytes:
#         """
#         Расшифрование данных произвольной длины.
#
#         Args:
#             data: зашифрованные байты (длина кратна 8)
#             padding: удалять ли PKCS#7 паддинг
#
#         Returns:
#             Расшифрованные данные
#         """
#         if len(data) % 8 != 0:
#             raise ValueError(f"Данные для расшифрования должны быть кратны 8 байтам, получено {len(data)}")
#
#         # Расшифровываем блоками по 8 байт
#         result = bytearray()
#         for i in range(0, len(data), 8):
#             block = data[i:i+8]
#             decrypted = self.decrypt_block(block)
#             result.extend(decrypted)
#
#         # Удаляем паддинг если нужно
#         if padding:
#             result = self._remove_pkcs7_padding(bytes(result))
#
#         return bytes(result)
#
#     @staticmethod
#     def _add_pkcs7_padding(data: bytes) -> bytes:
#         """
#         Добавляет PKCS#7 паддинг (дополняет до блока 8 байт).
#         """
#         padding_len = 8 - (len(data) % 8)
#         if padding_len == 0:
#             padding_len = 8
#         return data + bytes([padding_len] * padding_len)
#
#     @staticmethod
#     def _remove_pkcs7_padding(data: bytes) -> bytes:
#         """
#         Удаляет PKCS#7 паддинг.
#         """
#         if not data:
#             return data
#         padding_len = data[-1]
#         if padding_len > 8 or padding_len == 0:
#             raise ValueError("Неверный паддинг")
#         # Проверяем, что все байты паддинга одинаковые
#         if data[-padding_len:] != bytes([padding_len]) * padding_len:
#             raise ValueError("Неверный паддинг")
#         return data[:-padding_len]
#
#
# class MagmaFileProcessor:
#     """
#     Класс для работы с файлами: шифрование/расшифрование файлов,
#     выбор режима работы.
#     """
#
#     # Режимы работы блочного шифра (ECB - электронная кодовая книга)
#     MODES = {
#         'ecb': 'ECB (Electronic Codebook) - простой режим',
#         # Можно расширить: 'cbc', 'cfb', 'ofb', 'ctr'
#     }
#
#     def __init__(self, key: bytes, mode: str = 'ecb'):
#         """
#         Инициализация процессора файлов.
#
#         Args:
#             key: 32-байтный ключ
#             mode: режим работы ('ecb')
#         """
#         if mode.lower() not in self.MODES:
#             raise ValueError(f"Неподдерживаемый режим: {mode}. Доступны: {list(self.MODES.keys())}")
#
#         self._cipher = MagmaCipher(key)
#         self._mode = mode.lower()
#
#     def process_file(self, input_path: str, output_path: str, encrypt: bool = True) -> None:
#         """
#         Обработка файла (шифрование или расшифрование).
#
#         Args:
#             input_path: путь к входному файлу
#             output_path: путь к выходному файлу
#             encrypt: True - зашифровать, False - расшифровать
#         """
#         # Читаем входной файл
#         with open(input_path, 'rb') as f:
#             data = f.read()
#
#         # Обрабатываем данные
#         if encrypt:
#             result = self._cipher.encrypt(data)
#         else:
#             result = self._cipher.decrypt(data)
#
#         # Записываем результат
#         with open(output_path, 'wb') as f:
#             f.write(result)
#
#     @classmethod
#     def get_available_modes(cls) -> List[str]:
#         """Возвращает список доступных режимов работы."""
#         return list(cls.MODES.keys())
#
#     @classmethod
#     def validate_key(cls, key: bytes) -> bool:
#         """Проверяет, что ключ имеет правильную длину."""
#         return len(key) == 32
#
#
# # ============================================================================
# # ТЕСТИРОВАНИЕ НА КОНТРОЛЬНЫХ ПРИМЕРАХ ИЗ ГОСТ
# # ============================================================================
#
# def test_magma():
#     """
#     Проверка реализации на контрольных примерах из ГОСТ Р 34.12-2015.
#     Приложение А.2.
#     """
#     print("=" * 60)
#     print("ТЕСТИРОВАНИЕ ШИФРА МАГМА НА КОНТРОЛЬНЫХ ПРИМЕРАХ ИЗ ГОСТ")
#     print("=" * 60)
#
#     # Контрольный пример из ГОСТ (раздел А.2)
#     # Ключ (32 байта)
#     key_hex = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
#     master_key = bytes.fromhex(key_hex)
#
#     # Открытый текст (8 байт)
#     plaintext_hex = "fedcba9876543210"
#     plaintext = bytes.fromhex(plaintext_hex)
#
#     # Ожидаемый шифротекст из ГОСТ
#     expected_ciphertext_hex = "4ee901e5c2d8ca3d"
#     expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)
#
#     print(f"\nКлюч: {key_hex}")
#     print(f"Открытый текст: {plaintext_hex}")
#     print(f"Ожидаемый шифротекст: {expected_ciphertext_hex}")
#
#     # Шифрование
#     cipher = MagmaCipher(master_key)
#     ciphertext = cipher.encrypt_block(plaintext)
#     ciphertext_hex = ciphertext.hex()
#
#     print(f"\nПолученный шифротекст: {ciphertext_hex}")
#
#     # Проверка
#     if ciphertext == expected_ciphertext:
#         print("✓ ШИФРОВАНИЕ: УСПЕШНО! Результат совпадает с контрольным примером.")
#     else:
#         print("✗ ШИФРОВАНИЕ: ОШИБКА! Результат не совпадает с контрольным примером.")
#
#     # Расшифрование
#     decrypted = cipher.decrypt_block(ciphertext)
#     decrypted_hex = decrypted.hex()
#
#     print(f"Расшифрованный текст: {decrypted_hex}")
#
#     if decrypted == plaintext:
#         print("✓ РАСШИФРОВАНИЕ: УСПЕШНО! Восстановлен исходный текст.")
#     else:
#         print("✗ РАСШИФРОВАНИЕ: ОШИБКА!")
#
#     print("\n" + "=" * 60)
#     return ciphertext == expected_ciphertext and decrypted == plaintext
#
#
# def test_padding():
#     """
#     Тестирование паддинга и шифрования данных произвольной длины.
#     """
#     print("\n" + "=" * 60)
#     print("ТЕСТИРОВАНИЕ ПАДДИНГА И ШИФРОВАНИЯ ПРОИЗВОЛЬНОЙ ДЛИНЫ")
#     print("=" * 60)
#
#     # Простой ключ для теста
#     key = b'\x00' * 32
#     cipher = MagmaCipher(key)
#
#     # Тестовые данные
#     test_data = b"Hello, World! This is a test message for Magma cipher."
#
#     print(f"Исходные данные ({len(test_data)} байт): {test_data}")
#
#     # Шифрование с паддингом
#     encrypted = cipher.encrypt(test_data)
#     print(f"Зашифровано ({len(encrypted)} байт): {encrypted.hex()[:64]}...")
#
#     # Расшифрование
#     decrypted = cipher.decrypt(encrypted)
#
#     if decrypted == test_data:
#         print("✓ ПАДДИНГ: УСПЕШНО! Данные восстановлены корректно.")
#     else:
#         print("✗ ПАДДИНГ: ОШИБКА!")
#
#     return decrypted == test_data
#
#
# def interactive_mode():
#     """
#     Интерактивный режим: шифрование/расшифрование файлов по выбору пользователя.
#     """
#     print("\n" + "=" * 60)
#     print("ИНТЕРАКТИВНЫЙ РЕЖИМ РАБОТЫ")
#     print("=" * 60)
#
#     try:
#         # Ввод ключа
#         key_input = input("\nВведите ключ (32 байта в hex, 64 hex-символа): ").strip()
#         try:
#             key = bytes.fromhex(key_input)
#             if len(key) != 32:
#                 print(f"Ошибка: ключ должен быть 32 байта, получено {len(key)}")
#                 return
#         except ValueError:
#             print("Ошибка: ключ должен быть в hex-формате")
#             return
#
#         # Выбор режима
#         print(f"\nДоступные режимы: {MagmaFileProcessor.get_available_modes()}")
#         mode = input("Выберите режим работы (по умолчанию ecb): ").strip().lower() or 'ecb'
#
#         # Выбор действия
#         action = input("\nВыберите действие (1 - зашифровать, 2 - расшифровать): ").strip()
#
#         if action not in ['1', '2']:
#             print("Ошибка: выберите 1 или 2")
#             return
#
#         encrypt = (action == '1')
#         action_text = "зашифрования" if encrypt else "расшифрования"
#
#         # Пути к файлам
#         input_path = input(f"Введите путь к файлу для {action_text}: ").strip()
#         output_path = input("Введите путь для сохранения результата: ").strip()
#
#         # Проверка существования входного файла
#         if not os.path.exists(input_path):
#             print(f"Ошибка: файл {input_path} не найден")
#             return
#
#         # Обработка
#         processor = MagmaFileProcessor(key, mode)
#         processor.process_file(input_path, output_path, encrypt)
#
#         print(f"\nГотово! Результат сохранен в {output_path}")
#
#     except Exception as e:
#         print(f"Ошибка: {e}")
#
#
# if __name__ == "__main__":
#     # Запуск тестов
#     test1_passed = test_magma()
#     test2_passed = test_padding()
#
#     print("\n" + "=" * 60)
#     print("ИТОГИ ТЕСТИРОВАНИЯ")
#     print("=" * 60)
#     print(f"Контрольный пример ГОСТ: {'ПРОЙДЕН' if test1_passed else 'НЕ ПРОЙДЕН'}")
#     print(f"Тест паддинга: {'ПРОЙДЕН' if test2_passed else 'НЕ ПРОЙДЕН'}")
#
#     # Запрос на запуск интерактивного режима
#     print("\n" + "=" * 60)
#     run_interactive = input("Запустить интерактивный режим для работы с файлами? (y/n): ").strip().lower()
#     if run_interactive == 'y':
#         interactive_mode()
