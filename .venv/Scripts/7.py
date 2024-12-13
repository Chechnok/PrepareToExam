import re


def detect_sql_injection(user_input):
    """
    Функція для виявлення спроб SQL-ін'єкцій у введених даних.
    Перевіряє введення на наявність небезпечних символів або патернів.
    """
    # Патерни для пошуку SQL-ін'єкцій (базові правила)
    injection_patterns = [
        r"(--|\#)",  # SQL-коментарі
        r"(;|\sOR\s|\sAND\s)",  # Умови OR/AND або використання кількох запитів
        r"(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|UNION|CREATE|ALTER)\s",  # SQL-команди
        r"(\s'\s|' OR '|' AND ')",  # Підозрілі шаблони з апострофами
        r"(\b(0x[0-9A-Fa-f]+)\b)",  # Hexadecimal
        r"(\s=\s.*\s=\s.*)",  # Декілька умов із рівністю
    ]

    # Фільтрування небезпечних символів (наприклад, \')
    filtered_input = re.sub(r"[\'\";#\--]", '', user_input)

    # Перевірка введення на збіг із будь-яким патерном SQL-ін'єкції
    for pattern in injection_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return {
                "status": "warning",
                "message": f"Detected potential SQL injection! Pattern matched: {pattern}"
            }

    return {
        "status": "safe",
        "message": "Input is safe."
    }


# Функція для обробки вхідних даних із веб-форми
def process_form_data(form_data):
    """
    Аналізує масив даних, що приходять з форми, та перевіряє їх на SQL-ін’єкції.
    """
    results = {}
    for field, value in form_data.items():
        result = detect_sql_injection(value)
        results[field] = result
        if result['status'] == "warning":
            print(f"Warning: Potential SQL injection detected in field '{field}'")
            print(result['message'])
    return results


# Приклад використання
if __name__ == "__main__":
    # Тестові дані форми
    incoming_form_data = {
        "username": "user123",
        "password": "' OR 1=1 --",
        "email": "test@example.com; DROP TABLE users;",
        "age": "25"
    }

    print("Analyzing form data...\n")
    analysis_results = process_form_data(incoming_form_data)
    print("\nAnalysis Results:")
    for field, result in analysis_results.items():
        print(f"Field '{field}': {result}")
