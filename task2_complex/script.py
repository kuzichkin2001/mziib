import sys
import pefile


class FileSystemWatcher:
  def __init__(self, config_file_path='.fileinfo'):
    self.config_fp = config_file_path
    self.config = self.get_or_create_config_file()

  def read_content(self, file):
    file_contents = file.read()
    result = bin(int(file_contents.hex(), 16)).replace('0b', '')

    return result

  def read_binary(self, filename):
    with open(filename, 'rb') as file:
      file_contents = self.read_content(file)

      if len(file_contents) % 16 != 0:
        file_contents += (16 - len(file_contents)) * '0'

      hex_p = []
      for i in range(len(file_contents) // 16):
        hex_p.append(file_contents[16 * i:16 * (i + 1)])

      return hex_p

  def walk_along_dirs(self):
    current_dir = os.path.abspath('.')
    filesystem_metadata = []
    
    for elem in os.walk(current_dir):
      path, dirs, files = elem

      transformed_files = list(map(lambda x: f'{path}\\{x}', files))
      for filename in transformed_files:
        if not filename.endswith(self.config_fp):
          binaries = self.read_binary(filename)
          check_sum = self.calc_check_sum(binaries)
          filesystem_metadata.append((filename, check_sum))

    return filesystem_metadata

  def calc_check_sum(self, binaries):
    check_sum = 0
    for binary in binaries:
      check_sum ^= int('0b' + binary, 2)

    return check_sum

  def get_or_create_config_file(self):
    with open(self.config_fp, 'a+') as config_file:
      if len(config_file.read()) <= 0:
        config_file.write('')
        self.config = dict()
        return

      self.config = self.read_configuration_file()

  def get_file_checksum(self, filename):
    binary = self.read_binary(filename)
    checksum = self.calc_check_sum(binary)

    return checksum

  def write_to_configuration_file(self, check_sums):
    with open(self.config_fp, 'w') as config_file:
      config_file.write('\n'.join([f'{filename}: {check_sum}' for filename, check_sum in check_sums]))

  def read_configuration_file(self):
    with open(self.config_fp, 'r') as config_file:
      checksums = list(map(lambda x: x.rstrip('\n'), config_file.readlines()))

      checksums_view = dict()
      for checksum_row in checksums:
        filename, check_sum = checksum_row.split(': ')

        checksums_view[filename] = int(check_sum)

      return checksums_view


watcher = FileSystemWatcher()

checksums = watcher.read_configuration_file()

executable = sys.argv[0]
if len(checksums) == 0:
  watcher.write_to_configuration_file([(executable, 0)])

pe = pefile.PE(executable)
current_checksum = pe.generate_checksum()

print(f'previous checksums: {checksums}, current checksum: {current_checksum}')
if checksums.get(executable, -1) == -1:
  print('incorrect executable filename in .fileinfo')
  sys.exit(0)
if checksums.get(executable, -1) == 0:
  watcher.write_to_configuration_file([(executable, current_checksum)])
elif checksums.get(executable, -1) != 0:
  config_checksum = checksums[executable]
  if config_checksum != current_checksum:
    print('Changed!')
    watcher.write_to_configuration_file([(executable, current_checksum)])
    input()
  else:
    print('Same!')
    input()