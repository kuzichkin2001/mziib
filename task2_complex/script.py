import sys
import pefile
import subprocess
import psutil
import os

MAGIC_WORD = 0

def extract_process(p_name):
  print(f"Process name: {p_name}")

  pid = None
  for process in [p.info for p in psutil.process_iter(['pid', 'name'])]:
    if process['name'].endswith(p_name):
      pid = process['pid']
      break

  print(f"PID: {pid}")
  return psutil.Process(pid)

class CommandLineArguments:
  def __init__(self):
    self.current_executable = None
    self.running_copy = False
    self.original_executable = None

  def is_copy(self):
    return self.current_executable.find('.copy') != -1
  
  def extract_current_filename(self):
    return self.current_executable.split('\\')[-1]
  
  def extract_original_filename(self):
    return self.original_executable.split('\\')[-1]

class ArgvParser:
  @staticmethod
  def parse(argv):
    parsed_command = CommandLineArguments()
    
    if len(argv) == 1:
      parsed_command.current_executable = argv[0]
      parsed_command.running_copy = False
      parsed_command.original_executable = None
    elif len(argv) == 2:
      parsed_command.current_executable = argv[0]
      parsed_command.running_copy = argv[1] == 'true'
      parsed_command.original_executable = None
    else:
      parsed_command.current_executable = argv[0]
      parsed_command.running_copy = argv[1] == 'true'
      parsed_command.original_executable = argv[2]

    return parsed_command
  
class PEfileProcessor:
  def __init__(self, executable_path):
    self.executable = executable_path

  def read_checksum(self):
    pe = pefile.PE(self.executable)
    checksum = pe.OPTIONAL_HEADER.CheckSum
    pe.close()

    return checksum
  
  def write_checksum(self, to_executable):
    pe = pefile.PE(self.executable)
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(to_executable)

    print(f"Checksum is written: {pe.OPTIONAL_HEADER.CheckSum}, to file: {to_executable}")

    pe.close()

def main():
  arguments = ArgvParser.parse(sys.argv)

  print(arguments.current_executable)
  print(arguments.running_copy)
  print(arguments.original_executable)

  current_pe_processor = PEfileProcessor(arguments.current_executable)
  checksum = current_pe_processor.read_checksum()

  print(checksum)
  if checksum == MAGIC_WORD:
    original_fp = arguments.current_executable \
      if arguments.original_executable is None \
      else arguments.original_executable
    
    print(original_fp)
    
    temp_fp = arguments.current_executable.replace('.copy', '') \
      if arguments.is_copy() \
      else f'{arguments.current_executable[:-4]}.copy.exe'
    
    print(temp_fp)
    
    current_process_filename = arguments.extract_current_filename()
    current_process = extract_process(current_process_filename)

    if arguments.running_copy:
      current_pe_processor.write_checksum(temp_fp)
      subprocess.Popen([temp_fp, 'false', original_fp])

      current_process.terminate()
    
  else:
    if arguments.original_executable is not None:
      os.remove(arguments.original_executable)
      sys.exit(0)
    else:
      new_pe_processor = PEfileProcessor(arguments.current_executable)
      new_checksum = new_pe_processor.read_checksum()
      
      if checksum == new_checksum:
        print(f"Checksums are equal: {checksum}")
      else:
        print(f"Checksums are not equal:\nHeader data: {checksum}\nCurrently read data: {new_checksum}")


main()