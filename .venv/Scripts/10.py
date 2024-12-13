import random
import string
import logging

# Налаштування логгера для запису аварій чи неочікуваної поведінки
logging.basicConfig(
    filename="fuzz_tester.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def fuzz_tester(target_function, num_tests=1000):
    """
    Інструмент для fuzz-тестування.

    :param target_function: функція, що буде тестуватись
    :param num_tests: кількість випадкових тестів
    """
    for i in range(num_tests):
        # Генерація випадкового рядка
        test_input = generate_random_string()

        try:
            # Виконуємо функцію з тестовими даними
            result = target_function(test_input)

            # Перевірка на неочікувану поведінку (наприклад, NULL-результат)
            if result is None:
                logging.warning(f"Unexpected behavior detected: input={test_input} | result=None")

        except Exception as e:
            # Записуємо у журнал інформацію про збій
            logging.error(f"Crash detected: input={test_input} | Exception={str(e)}")


def generate_random_string(max_length=100):
    """
    Генерує випадковий рядок.

    :param max_length: максимальна довжина рядка
    :return: випадковий рядок
    """
    length = random.randint(1, max_length)
    return ''.join(random.choices(string.printable, k=length))


# Приклад функції, яку будемо тестувати
def example_function(input_string):
    """
    Тестова функція для обробки рядка.
    Викликає помилку для демонстрації, якщо в рядку є спеціальні символи.
    """
    # Якщо рядок містить цифри, викликаємо ValueError
    if any(char.isdigit() for char in input_string):
        raise ValueError("Input cannot contain digits!")

    # Уявна обробка рядка
    return input_string[::-1]  # Реверс рядка


if __name__ == "__main__":
    print("Starting fuzz tester...")

    # Виклики fuzz-тестера на тестовій функції
    fuzz_tester(example_function, num_tests=1000)

    print("Fuzz testing complete. Check 'fuzz_tester.log' for results.")
