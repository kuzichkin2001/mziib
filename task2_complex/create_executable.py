import os, sys

print(sys.argv)

working_dir = os.path.dirname(os.path.realpath(__file__))
build_dir = f'{working_dir}\\build\\'
script = f'script.py'
script_location = f'{working_dir}\\{script}'
observable_exe = f'{script[:-3]}_complex.exe'

os.system(f"pyinstaller --onefile --distpath . --noconfirm -n {observable_exe} {script_location}")
