# MagmaCrypt — Реализация блочного шифра «Магма» и режимов его работы по ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015

## Описание

**MagmaCrypt** — это программная реализация блочного шифра «Магма» (Magma) и всех шести режимов его работы в соответствии с российскими государственными стандартами:

- **ГОСТ Р 34.12-2015** — блочные шифры (алгоритм «Магма» с длиной блока 64 бита и ключом 256 бит);
- **ГОСТ Р 34.13-2015** — режимы работы блочных шифров (ECB, CBC, CFB, OFB, CTR, MAC).

Проект предназначен для учебных целей, а также может использоваться как основа для разработки прикладных средств криптографической защиты информации.

## Возможности

- **Базовый шифр «Магма»**:
  - Фиксированные S-блоки из ГОСТ;
  - Развертывание 256-битного ключа в 32 раундовых ключа;
  - Функция Фейстеля g (сложение по модулю 2³², нелинейное преобразование t, циклический сдвиг на 11 бит);
  - Шифрование и расшифрование отдельных 64-битных блоков;
  - Обработка данных произвольной длины с процедурой дополнения 2.

- **Режимы работы** (все 6 по ГОСТ Р 34.13-2015):
  - **ECB** (Electronic Codebook) — простая замена;
  - **CBC** (Cipher Block Chaining) — простая замена с зацеплением;
  - **CFB** (Cipher Feedback) — гаммирование с обратной связью по шифртексту;
  - **OFB** (Output Feedback) — гаммирование с обратной связью по выходу;
  - **CTR** (Counter) — гаммирование с использованием счетчика;
  - **MAC** (Message Authentication Code) — выработка имитовставки.

- **Интерактивная оболочка**:
  - Ввод ключа в hex-формате (64 символа);
  - Выбор режима работы;
  - Шифрование/расшифрование файлов;
  - Генерация и проверка имитовставки (MAC).

- **Отладочная версия**:
  - Пошаговый вывод промежуточных значений на каждом раунде;
  - Визуальная верификация соответствия ГОСТ.

- **Автоматическое тестирование**:
  - 37 тестов на основе pytest;
  - Контрольные примеры из ГОСТ Р 34.13-2015 (Приложение А.2);
  - Проверка всех режимов и вспомогательных функций.

## Структура проекта
MagmaCrypt/
├── magma_code.py # Базовый шифр "Магма"
├── magma_modes.py # Режимы работы (ECB, CBC, CFB, OFB, CTR, MAC)
├── main.py # Интерактивная оболочка для работы с файлами
├── magma_base_debug.py # Отладочная версия с пошаговым выводом
├── test_magma_modes.py # Автоматические тесты (pytest)
├── pyproject.toml # Конфигурация Poetry
└── README.md # Документация проекта


## Установка

### 1. Клонирование репозитория

```
git clone -b develop https://github.com/Rapunzel-Chan/magmacrypt.git
cd MagmaCrypt
```
### 2. Создание и активация виртуального окружения
Windows:

```
python -m venv venv
.\venv\Scripts\activate
```

Linux/macOS:

```
python3 -m venv venv
source venv/bin/activate
```

### 3. Установка зависимостей
```
pip install -r requirements.txt
```
Или 
```
poetry install
```

## Использование
### 1. Интерактивный режим

Запустите интерактивную оболочку:

```
python main.py
```
Программа предложит:

- Ввести ключ шифрования (64 hex-символа);

- режим работы (1-6);

- Выбрать действие (зашифровать/расшифровать файл или работать с MAC);

- Указать пути к входному и выходному файлам.

Пример ключа (из ГОСТ):
```
ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
``` 

### 2. Отладочная версия
Для пошагового просмотра процесса шифрования:

``` 
python magma_base_debug.py
``` 

Выберите:

1 — отладка зашифрования на контрольном примере;

2 — отладка расшифрования;

q — выход.

### 3. Автоматическое тестирование
Запуск всех тестов:

``` 
pytest test_magma_modes.py -v
``` 
Запуск конкретного класса тестов:

``` 
pytest test_magma_modes.py::TestECB -v
pytest test_magma_modes.py::TestMAC -v
``` 

Контрольные примеры: 
- Базовый шифр «Магма»

| Параметр             | Значение                                                         |
|----------------------|------------------------------------------------------------------|
| Ключ                 | ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff |
| Открытый текст       | 	fedcba9876543210                                                |
| Ожидаемый шифротекст | 	4ee901e5c2d8ca3d                                                |

- Режимы работы (Приложение А.2 ГОСТ Р 34.13-2015)

| Режим	| Контрольный пример  | Результат         |
|-------|---------------------|-------------------|
| ECB   |   Таблица А.7       |✓ совпадает        |
| CTR   | 	Таблица А.8	      |✓ совпадает        | 
| CBC   | 	Таблица А.10      |✓ совпадает        |
| CFB   | 	Таблица А.11      |✓ совпадает        |
| OFB   | 	Таблица А.9       |✓ совпадает        |
| MAC   | 	Таблица А.12      |154e7210 (32 бита) |


## Требования
Python: 3.10 или выше

## Зависимости:

- pytest — для автоматического тестирования

- pytest-cov — для оценки покрытия кода (опционально)

Полный список зависимостей указан в pyproject.toml или requirements.txt.

## Результаты тестирования

============================= test session starts =============================
collected 37 items

test_magma_modes.py::TestECB::test_encrypt PASSED                        [  2%]
test_magma_modes.py::TestECB::test_decrypt PASSED                        [  5%]
test_magma_modes.py::TestECB::test_encrypt_decrypt_roundtrip PASSED      [  8%]
test_magma_modes.py::TestECB::test_padding PASSED                        [ 10%]
test_magma_modes.py::TestCBC::test_encrypt PASSED                        [ 13%]
test_magma_modes.py::TestCBC::test_decrypt PASSED                        [ 16%]
test_magma_modes.py::TestCBC::test_encrypt_decrypt_roundtrip PASSED      [ 18%]
test_magma_modes.py::TestCBC::test_different_iv PASSED                   [ 21%]
test_magma_modes.py::TestCTR::test_encrypt PASSED                        [ 24%]
test_magma_modes.py::TestCTR::test_decrypt PASSED                        [ 27%]
test_magma_modes.py::TestCTR::test_encrypt_decrypt_roundtrip PASSED      [ 29%]
test_magma_modes.py::TestCTR::test_counter_increment PASSED              [ 32%]
test_magma_modes.py::TestCFB::test_encrypt PASSED                        [ 35%]
test_magma_modes.py::TestCFB::test_decrypt PASSED                        [ 37%]
test_magma_modes.py::TestCFB::test_encrypt_decrypt_roundtrip PASSED      [ 40%]
test_magma_modes.py::TestCFB::test_different_s[8] PASSED                 [ 43%]
test_magma_modes.py::TestCFB::test_different_s[16] PASSED                [ 45%]
test_magma_modes.py::TestCFB::test_different_s[32] PASSED                [ 48%]
test_magma_modes.py::TestCFB::test_different_s[64] PASSED                [ 51%]
test_magma_modes.py::TestOFB::test_encrypt PASSED                        [ 54%]
test_magma_modes.py::TestOFB::test_decrypt PASSED                        [ 56%]
test_magma_modes.py::TestOFB::test_encrypt_decrypt_roundtrip PASSED      [ 59%]
test_magma_modes.py::TestOFB::test_encrypt_equals_decrypt PASSED         [ 62%]
test_magma_modes.py::TestMAC::test_generate_32bit PASSED                 [ 64%]
test_magma_modes.py::TestMAC::test_generate_64bit PASSED                 [ 67%]
test_magma_modes.py::TestMAC::test_verify_correct PASSED                 [ 70%]
test_magma_modes.py::TestMAC::test_verify_incorrect PASSED               [ 72%]
test_magma_modes.py::TestMAC::test_verify_modified_data PASSED           [ 75%]
test_magma_modes.py::TestMAC::test_empty_message PASSED                  [ 78%]
test_magma_modes.py::TestMAC::test_different_s_values PASSED             [ 81%]
test_magma_modes.py::TestMAC::test_auxiliary_keys PASSED                 [ 83%]
test_magma_modes.py::TestCrossMode::test_ecb_cbc_consistency PASSED      [ 86%]
test_magma_modes.py::TestCrossMode::test_cfb_ofb_are_different_modes PASSED [ 89%]
test_magma_modes.py::TestCrossMode::test_ctr_consistency_with_different_iv PASSED [ 91%]
test_magma_modes.py::TestHelperFunctions::test_xor_bytes PASSED          [ 94%]
test_magma_modes.py::TestHelperFunctions::test_msb PASSED                [ 97%]
test_magma_modes.py::TestHelperFunctions::test_lsb PASSED                [100%]

============================= 37 passed in 0.41s ==============================

## Лицензия

Проект разработан в учебных целях. Код может использоваться для изучения криптографических алгоритмов и стандартов.

## Создатель

В случае возникновения вопросов, нахождения багов или предложений по улучшению кода, можно обратиться к разработчику
по e-mail: rapuncel.chan24@gmail.com.
