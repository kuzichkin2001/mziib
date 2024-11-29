import pefile
import os

start_exe_path = './dist/script1.exe'
finish_exe_path = './dist/script.exe'

def hook():
    pe = pefile.PE(start_exe_path)
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.write(finish_exe_path)
    pe.close()

    os.remove(start_exe_path)

if __name__ == '__main__':
    hook()