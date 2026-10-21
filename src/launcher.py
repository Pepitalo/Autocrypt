#!/usr/bin/env python3
"""
Centralised launching script to fix relative import issues (launches all scripts as modules)
and to simplify the use all programs involved
WARNING : Does not close threads properly by the way. So if one of the programs uses threads
please just spam ^C
"""

import sys
import os
from pathlib import Path

errors = 0

def check(label, got, expected):
    global errors
    if callable(got):
        try:
            got = got()
        except Exception as e:
            print(f"ERROR  {label} :")
            print(f"\t- {type(e).__name__}: {e}")
            errors += 1
            return
    if got == expected:
        print(f"PASSED {label}")
    else:
        print(f"FAILED {label} :")
        print(f"\t- Expected : {expected}")
        print(f"\t- Got : {got}")
        errors+=1

# Not sure if you guys are using a venv so I put an option in the launcher to be safe
ROOT_DIR = Path(__file__).parent.absolute()
VENV_PATH = ROOT_DIR.parent.parent / ".venv"           #generic path, to be changed if need be


def is_git_bash():
    """Detects Git Bash on Windows to fix Sacha's issue with the test program"""
    return os.name == 'nt' and bool(os.environ.get('MSYSTEM'))


def activate_venv():
    """Activates the python venv"""
    if VENV_PATH.exists():
        if os.name == 'nt' and not is_git_bash():
            site_packages = VENV_PATH / "Lib" / "site-packages"
            bin_dir = VENV_PATH / "Scripts"
            sep = ";"
        else:
            site_packages = VENV_PATH / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
            bin_dir = VENV_PATH / "bin"
            sep = ":"

        if site_packages.exists():
            sys.path.insert(0, str(site_packages))

        os.environ['VIRTUAL_ENV'] = str(VENV_PATH)
        os.environ['PATH'] = f"{bin_dir}{sep}{os.environ.get('PATH', '')}"
    else:
        print(f"Warning: Unable to find venv at {VENV_PATH}")

# Activating the venv must be done BEFORE adding the root directory always
activate_venv()
sys.path.insert(0, str(ROOT_DIR))


def clear_screen():
    os.system('cls' if os.name == 'nt' and not is_git_bash() else 'clear')


def print_menu(spec = ""):
    if spec == "" :
        menu = {
            "1": ("GIFT Cipher", "gift_cipher.py"),
            "2": ("PRESENT Cipher", "present_cipher_64_bit.py"),
            "3": ("AES Cipher", "aes.py"),
            "4": ("ALZETTE (ARX) Cipher", "alzette_cipher.py"),
            "5": ("SPECK Cipher", "speck_cipher.py"),
            "6": ("Linear Attack", "linear_cryptanalysis.py"),
            "7": ("Differential Attack", "differential_cryptanalysis.py"),
            "8": ("Tools", "tools.py"),
            "9": ("[NOT FOR DEMO] : Tests", "tests"),
            "10": ("[NOT FOR DEMO] : Extra gift tests", "tests/test_gift.py"),
            "0": ("Quit", None),
        }
    elif spec ==  "tests/" :
        menu = {
            "1": ("AES Test", "aes_test.py"),
            "2": ("Differential Test", "differential_cryptanalysis_test.py"),
            "3": ("GIFT Test", "gift_test.py"),
            "4": ("Linear Test", "linear_cryptanalysis_test.py"),
            "5": ("MILP Test", "milp_test.py"),
            "6": ("PRESENT Test", "present_test.py"),
            "7": ("Tools Test", "tools_test.py"),
            "8": ("New gift test", "new_gift_test.py"),
            "0": ("Quit", None),
        }
    print("\n" + "=" * 50)
    print("ARTISHOW - Launching system")
    print("=" * 50 + "\n")
    
    for key, (name, _) in menu.items():
        print(f"  [{key:>2}] {name}")
    
    print("\n" + "-" * 50)
    return menu


def run_module(module_path):
    if not module_path:
        return False
    
    full_path = ROOT_DIR / module_path
    
    if not full_path.exists():
        print(f"\nError: {module_path} not found")
        input("\nPress enter to continue...")
        return True
    
    print(f"\nLaunching: {module_path}\n")
    
    try:    #This try except is CAPITAL to the working of this program, do not modify this structure
        os.chdir(full_path.parent)
        with open(full_path, 'r', encoding='utf-8') as f:
            module_globals = {**globals(), '__name__': '__main__', '__file__': str(full_path)}
            exec(compile(f.read(), module_path, 'exec'), module_globals)
    except SystemExit:
        # Captures exit() called by the module
        print("\n\n== Program terminated ==")
    except KeyboardInterrupt:
        print("\n\n== Interruption (Ctrl+C) ==")
    except Exception as e:
        print(f"\n== Error: {e} ==")
        import traceback
        traceback.print_exc()
    finally:
        os.chdir(ROOT_DIR)
        # Rouvrir stdin si fermé
        if sys.stdin.closed:
            tty = 'con' if (os.name == 'nt' and not is_git_bash()) else '/dev/tty'
            sys.stdin = open(tty, 'r')
        try:
            input("\nPress enter to go back to the menu...")
        except:
            # If input fails, we wait 2 seconds (zzzZZZ)
            import time
            time.sleep(2)
    
    return True

def run_sage_module(module_path):
    if not module_path:
        return False

    full_path = ROOT_DIR / module_path

    if not full_path.exists():
        print(f"\nError: {module_path} not found")
        input("\nPress enter to continue...")
        return True

    print(f"\nLaunching: {module_path} (via sage)\n")

    try:
        import subprocess
        subprocess.run(["sage", "-python", str(full_path)], cwd=str(full_path.parent))
    except KeyboardInterrupt:
        print("\n\n== Interruption (Ctrl+C) ==")
    finally:
        input("\nPress enter to go back to the menu...")

    return True


def main(spec = ""):

    if len(sys.argv) > 1:

        menu = print_menu("tests/")
        module_label, module_path = menu[sys.argv[1][2:].strip()]
        run_module("tests/" + module_path)

        sys.exit(errors)
        return

    while True:
        clear_screen()
        menu = print_menu(spec)
        
        try:
            choice = input("Choice: ").strip()

            if choice not in menu :
                print(f"\nInvalid choice: {choice}")
                input("\nPress enter to contiue...")

            module_label, module_path = menu[choice]
            
            if choice == "0":
                print("\n=== Closing launcher ===\n")
                sys.exit(0)

            if choice in menu and module_label != "Tests":
                if module_path == "differential_cryptanalysis.py":
                    run_sage_module(spec + module_path)
                else:
                    run_module(spec + module_path)

            else :
                main("tests/")

            """
            if choice in menu:
                _, module_path = menu[choice]
                if module_path != "tests" :
                    run_module(module_path)
                else :
                    clear_screen()
                    menu = print_menu("tests")
                    try:
                        choice = input("Choice: ").strip()
                        if choice == "0":
                            print("\n=== Closing launcher ===\n")
                            sys.exit(0)
                        if choice in menu:
                            _, module_path = menu[choice]
                            module_path = "tests/" + module_path
                            run_module(module_path)
                        else:
                            print(f"\nInvalid choice: {choice}")
                            input("\nPress enter to contiue...")
                    except KeyboardInterrupt:
                        print("\n\n=== Closing launcher ===\n")
                        sys.exit(0)
            
            else:
                print(f"\nInvalid choice: {choice}")
                input("\nPress enter to contiue...")
            """
        
        except KeyboardInterrupt:
            print("\n\n=== Closing launcher ===\n")
            sys.exit(0)


if __name__ == "__main__":
    main()