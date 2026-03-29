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
    """Интерактивный режим с циклом для повторных операций."""
    print("\n" + "=" * 70)
    print("ИНТЕРАКТИВНЫЙ РЕЖИМ РАБОТЫ")
    print("=" * 70)

    while True:
        try:
            print("\n--- НОВАЯ ОПЕРАЦИЯ ---")

            # 1. Ввод ключа
            print("\n[1] Введите секретный ключ (или 'q' для выхода)")
            print("    Ключ: 64 hex-символа (0-9, A-F, a-f)")
            print("    Пример: ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

            key_input = input("Ключ: ").strip()

            # Очистка от пробелов и невидимых символов
            key_input = ''.join(key_input.split())
            key_input = key_input.replace('\n', '').replace('\r', '').replace('\t', '')

            if key_input.lower() == 'q':
                print("Выход из программы.")
                break

            # Проверка длины
            if len(key_input) != 64:
                print(f"Ошибка: нужно 64 hex-символа, получено {len(key_input)}")
                print(f"Введено: {key_input[:20]}{'...' if len(key_input) > 20 else ''}")
                continue

            # Проверка символов
            valid_chars = set('0123456789abcdefABCDEF')
            invalid_chars = [c for c in key_input if c not in valid_chars]
            if invalid_chars:
                print(f"Ошибка: недопустимые символы: {invalid_chars}")
                print("Допустимы только: 0-9, A-F, a-f")
                continue

            try:
                key = bytes.fromhex(key_input)
                if len(key) != 32:
                    print(f"Ошибка: ключ должен быть 32 байта, получено {len(key)}")
                    continue
                print(f"✓ Ключ принят (32 байта)")
                print(f"  Hex: {key.hex()}")
            except ValueError as e:
                print(f"Ошибка преобразования hex: {e}")
                continue

            # 2. Выбор действия
            print("\n[2] Выберите действие")
            print("    1 - Зашифровать файл")
            print("    2 - Расшифровать файл")
            print("    0 - Ввести другой ключ")

            action = input("\nДействие (0-2): ").strip()

            if action == '0':
                continue
            if action not in ['1', '2']:
                print("Ошибка: выберите 1, 2 или 0")
                continue

            encrypt = (action == '1')
            action_text = "зашифрования" if encrypt else "расшифрования"

            # 3. Путь к входному файлу
            print(f"\n[3] Введите путь к файлу для {action_text}")
            print("    Примеры:  test.txt, folder/test.txt, C:/path/test.txt")
            input_path = input("Путь: ").strip()

            if not os.path.exists(input_path):
                print(f"Ошибка: файл '{input_path}' не найден")
                print(f"Текущая папка: {os.getcwd()}")
                continue

            # Получаем размер файла
            file_size = os.path.getsize(input_path)
            print(f"✓ Файл найден. Размер: {file_size} байт")

            # 4. Путь к выходному файлу
            default_output = input_path + (".enc" if encrypt else ".dec")
            print(f"\n[4] Выходной файл (Enter = {default_output})")
            output_path = input("Путь: ").strip()
            if not output_path:
                output_path = default_output

            # Создаем папку для выходного файла, если нужно
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"  Создана папка: {output_dir}")

            # 5. Подтверждение
            print("\n" + "-" * 50)
            print("ПАРАМЕТРЫ ОПЕРАЦИИ:")
            print(f"  Операция: {'ЗАШИФРОВАНИЕ' if encrypt else 'РАСШИФРОВАНИЕ'}")
            print(f"  Ключ: {key.hex()[:16]}...{key.hex()[-16:]}")
            print(f"  Входной файл: {input_path} ({file_size} байт)")
            print(f"  Выходной файл: {output_path}")
            print("-" * 50)

            confirm = input("\nВыполнить операцию? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Операция отменена")
                continue

            # 6. Выполнение
            print("\n⏳ Выполняется операция...")

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

                print(f"\n✓ ГОТОВО! Результат сохранен в {output_path}")
                print(f"  Размер результата: {len(result)} байт")

            except ValueError as e:
                if "padding" in str(e).lower():
                    print(f"\n✗ ОШИБКА: {e}")
                    print("  Скорее всего, ключ неверный или файл поврежден.")
                else:
                    raise

            # 7. Спросить, продолжить ли
            again = input("\nВыполнить еще одну операцию? (y/n): ").strip().lower()
            if again != 'y':
                print("Выход из программы.")
                break

        except KeyboardInterrupt:
            print("\n\nПрервано пользователем.")
            break
        except Exception as e:
            print(f"\nОшибка: {e}")
            continue


# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    # Запуск теста ГОСТ
    test_magma()

    # Запрос на запуск интерактивного режима
    print("\n" + "=" * 70)
    run_interactive = input("Запустить интерактивный режим для работы с файлами? (y/n): ").strip().lower()
    if run_interactive == 'y':
        interactive_mode()
