import pefile
import hashlib
import os


def analyze_pe_file(file_path):
    try:
        # Завантаження PE-файлу
        pe = pefile.PE(file_path)
        print(f"Analyzing PE file: {file_path}")

        # Розрахунок хеша файлу
        with open(file_path, "rb") as f:
            file_data = f.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            print(f"SHA-256 Hash: {sha256_hash}")

        # Огляд заголовків файлу
        print("\n[Basic Headers Info]")
        print(f"Machine Architecture: {hex(pe.FILE_HEADER.Machine)}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
        print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

        # Перевірка секцій файлу
        print("\n[Sections Info]")
        for section in pe.sections:
            print(f"Section Name: {section.Name.decode().strip()}")
            print(f"Virtual Address: {hex(section.VirtualAddress)}")
            print(f"Virtual Size: {section.Misc_VirtualSize}")
            print(f"Raw Size: {section.SizeOfRawData}")
            print(f"Entropy: {section.get_entropy():.2f}")
            print("-" * 30)

        # Аналіз імпортованих функцій і DLL
        print("\n[Imported DLLs]")
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"Imported DLL: {entry.dll.decode()}")
                for imp in entry.imports:
                    print(f"  {hex(imp.address)} {imp.name.decode() if imp.name else 'Unknown'}")
        else:
            print("No imported DLLs found.")

        # Аналіз експортованих функцій
        print("\n[Exported Functions]")
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"Exported Function: {exp.name.decode() if exp.name else 'Unknown'}")
        else:
            print("No exported functions found.")

        # Виявлення Packer/Protector
        print("\n[Possible Packers/Protectors]")
        detected = pe.get_overlay_data() is not None
        print("Packed/Protected: Yes" if detected else "Packed/Protected: No")

        # Закриваємо об'єкт PE
        pe.close()

    except FileNotFoundError:
        print("Error: File not found.")
    except pefile.PEFormatError:
        print("Error: The file is not a valid PE format.")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    file_path = input("Enter the path to the PE file: ").strip()

    if os.path.exists(file_path):
        analyze_pe_file(file_path)
    else:
        print("File does not exist.")
