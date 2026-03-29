"""
ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.
Программа для шифрования/расшифрования файлов с использованием шифра Магма.
Поддерживаются все 6 режимов работы:
- ECB, CBC, CFB, OFB, CTR, MAC
"""

import os
from typing import Optional

from magma_code import MagmaCipher, test_magma
from magma_modes import (
    ModeECB, ModeCBC, ModeCFB, ModeOFB, ModeCTR, ModeMAC,
    _int_to_bytes, _bytes_to_int
)


# ============================================================================
# ИНТЕРАКТИВНЫЙ РЕЖИМ
# ============================================================================

def interactive_mode():
    """Интерактивный режим с выбором режима работы."""
    print("\n" + "=" * 70)
    print("ИНТЕРАКТИВНЫЙ РЕЖИМ РАБОТЫ (ГОСТ Р 34.13-2015)")
    print("=" * 70)

    while True:
        try:
            print("\n--- НОВАЯ ОПЕРАЦИЯ ---")

            # 1. Ввод ключа
            print("\n[1] Введите секретный ключ (или 'q' для выхода)")
            print("    Ключ: 64 hex-символа (0-9, A-F, a-f)")
            print("    Пример: ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

            key_input = input("Ключ: ").strip()
            key_input = ''.join(key_input.split())
            key_input = key_input.replace('\n', '').replace('\r', '').replace('\t', '')

            if key_input.lower() == 'q':
                print("Выход из программы.")
                break

            if len(key_input) != 64:
                print(f"Ошибка: нужно 64 hex-символа, получено {len(key_input)}")
                continue

            valid_chars = set('0123456789abcdefABCDEF')
            if any(c not in valid_chars for c in key_input):
                print("Ошибка: недопустимые символы. Допустимы только 0-9, A-F, a-f")
                continue

            try:
                key = bytes.fromhex(key_input)
                print(f"✓ Ключ принят (32 байта)")
            except ValueError as e:
                print(f"Ошибка: {e}")
                continue

            cipher = MagmaCipher(key)

            # 2. Выбор режима
            print("\n[2] Выберите режим работы (ГОСТ Р 34.13-2015)")
            print("    1 - ECB  (Electronic Codebook) - простая замена")
            print("    2 - CBC  (Cipher Block Chaining) - простая замена с зацеплением")
            print("    3 - CFB  (Cipher Feedback) - гаммирование с обратной связью по шифртексту")
            print("    4 - OFB  (Output Feedback) - гаммирование с обратной связью по выходу")
            print("    5 - CTR  (Counter) - гаммирование")
            print("    6 - MAC  (Message Authentication Code) - выработка имитовставки")
            print("    0 - Ввести другой ключ")

            mode_choice = input("\nВыберите режим (0-6): ").strip()

            if mode_choice == '0':
                continue
            if mode_choice not in ['1', '2', '3', '4', '5', '6']:
                print("Ошибка: выберите 1-6 или 0")
                continue

            # 3. Для режимов, требующих IV
            iv = None
            nonce = None

            if mode_choice in ['2', '3', '4']:  # CBC, CFB, OFB
                print(f"\n[3] Введите вектор инициализации (IV)")
                print(f"    IV должен быть 8 байт (16 hex-символов)")
                print("    Пример: 1234567890abcdef")
                iv_hex = input("IV: ").strip().replace(' ', '')
                if len(iv_hex) != 16:
                    print(f"Ошибка: IV должен быть 16 hex-символов (8 байт), получено {len(iv_hex)}")
                    continue
                try:
                    iv = bytes.fromhex(iv_hex)
                except ValueError:
                    print("Ошибка: IV должен быть в hex-формате")
                    continue

            elif mode_choice == '5':  # CTR
                print(f"\n[3] Введите nonce (уникальное значение)")
                print(f"    Nonce может быть от 1 до 8 байт (2-16 hex-символов)")
                print("    Пример: 12345678")
                nonce_hex = input("Nonce: ").strip().replace(' ', '')
                if len(nonce_hex) < 2 or len(nonce_hex) > 16:
                    print("Ошибка: nonce должен быть от 2 до 16 hex-символов (1-8 байт)")
                    continue
                try:
                    nonce = bytes.fromhex(nonce_hex)
                except ValueError:
                    print("Ошибка: nonce должен быть в hex-формате")
                    continue

            # 4. Для MAC - отдельная логика
            if mode_choice == '6':
                print("\n[3] Режим MAC (имитовставка)")
                print("    1 - Сгенерировать MAC для файла")
                print("    2 - Проверить MAC файла")
                mac_action = input("\nВыберите действие (1-2): ").strip()

                if mac_action not in ['1', '2']:
                    print("Ошибка: выберите 1 или 2")
                    continue

                input_path = input("\nВведите путь к файлу: ").strip()
                if not os.path.exists(input_path):
                    print(f"Ошибка: файл '{input_path}' не найден")
                    continue

                file_size = os.path.getsize(input_path)
                print(f"✓ Файл найден. Размер: {file_size} байт")

                # Длина MAC (по умолчанию 32 бита)
                s_input = input("Длина MAC в битах (по умолчанию 32, от 1 до 64): ").strip()
                s = 32 if not s_input else int(s_input)
                if s < 1 or s > 64:
                    print("Ошибка: длина MAC должна быть от 1 до 64 бит")
                    continue

                mac_mode = ModeMAC(cipher)

                with open(input_path, 'rb') as f:
                    data = f.read()

                if mac_action == '1':
                    mac_value = mac_mode.generate(data, s)
                    output_path = input("Введите путь для сохранения MAC: ").strip()
                    output_dir = os.path.dirname(output_path)
                    if output_dir and not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    with open(output_path, 'wb') as f:
                        f.write(mac_value)
                    print(f"\n✓ MAC ({s} бит): {mac_value.hex()}")
                    print(f"  Сохранен в {output_path}")

                else:  # mac_action == '2'
                    mac_hex = input("Введите MAC (hex): ").strip().replace(' ', '')
                    try:
                        mac_value = bytes.fromhex(mac_hex)
                    except ValueError:
                        print("Ошибка: MAC должен быть в hex-формате")
                        continue
                    is_valid = mac_mode.verify(data, mac_value, s)
                    print(f"\nMAC: {mac_value.hex()}")
                    print(f"Результат проверки: {'✓ ПРОЙДЕНА (данные подлинны)' if is_valid else '✗ НЕ ПРОЙДЕНА (данные изменены!)'}")

                # Спросить о продолжении
                again = input("\nВыполнить еще одну операцию? (y/n): ").strip().lower()
                if again != 'y':
                    break
                continue

            # 5. Для шифрования/расшифрования
            print("\n[4] Выберите действие")
            print("    1 - Зашифровать файл")
            print("    2 - Расшифровать файл")
            action = input("\nДействие (1-2): ").strip()

            if action not in ['1', '2']:
                print("Ошибка: выберите 1 или 2")
                continue

            encrypt = (action == '1')
            action_text = "зашифрования" if encrypt else "расшифрования"

            # 6. Путь к входному файлу
            print(f"\n[5] Введите путь к файлу для {action_text}")
            input_path = input("Путь: ").strip()

            if not os.path.exists(input_path):
                print(f"Ошибка: файл '{input_path}' не найден")
                print(f"Текущая папка: {os.getcwd()}")
                continue

            file_size = os.path.getsize(input_path)
            print(f"✓ Файл найден. Размер: {file_size} байт")

            # 7. Путь к выходному файлу
            ext = ".enc" if encrypt else ".dec"
            default_output = input_path + ext
            print(f"\n[6] Выходной файл (Enter = {default_output})")
            output_path = input("Путь: ").strip()
            if not output_path:
                output_path = default_output

            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"  Создана папка: {output_dir}")

            # 8. Создание экземпляра режима
            if mode_choice == '1':
                mode = ModeECB(cipher)
                mode_name = "ECB"
            elif mode_choice == '2':
                mode = ModeCBC(cipher, iv)
                mode_name = "CBC"
            elif mode_choice == '3':
                mode = ModeCFB(cipher, iv)
                mode_name = "CFB"
            elif mode_choice == '4':
                mode = ModeOFB(cipher, iv)
                mode_name = "OFB"
            elif mode_choice == '5':
                mode = ModeCTR(cipher, nonce)
                mode_name = "CTR"
            else:
                continue

            # 9. Подтверждение
            print("\n" + "-" * 50)
            print("ПАРАМЕТРЫ ОПЕРАЦИИ:")
            print(f"  Режим: {mode_name}")
            print(f"  Операция: {'ЗАШИФРОВАНИЕ' if encrypt else 'РАСШИФРОВАНИЕ'}")
            print(f"  Ключ: {key.hex()[:16]}...{key.hex()[-16:]}")
            if iv:
                print(f"  IV: {iv.hex()}")
            if nonce:
                print(f"  Nonce: {nonce.hex()}")
            print(f"  Входной файл: {input_path} ({file_size} байт)")
            print(f"  Выходной файл: {output_path}")
            print("-" * 50)

            confirm = input("\nВыполнить операцию? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Операция отменена")
                continue

            # 10. Выполнение
            print("\n⏳ Выполняется операция...")

            with open(input_path, 'rb') as f:
                data = f.read()

            try:
                if encrypt:
                    result = mode.encrypt(data)
                else:
                    result = mode.decrypt(data)

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

            # 11. Продолжить?
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
    # Тест базового шифра
    test_magma()

    # Запрос на запуск интерактивного режима
    print("\n" + "=" * 70)
    run_interactive = input("Запустить интерактивный режим для работы с файлами? (y/n): ").strip().lower()
    if run_interactive == 'y':
        interactive_mode()