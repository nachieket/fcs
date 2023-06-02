import platform
import subprocess
import shutil
import sys
import time

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class SystemCheck:
  info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
  error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

  decorator = CustomDecorator(info_logger, error_logger)

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def run_command(self, command_str):
    self.info_logger.info(f'command to be executed: {command_str}')
    command = command_str.split()

    try:
      process = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors='replace',
        timeout=300
      )
      if process.stdout:
        self.info_logger.info(process.stdout)
      if process.stderr:
        self.error_logger.info(process.stderr)
      return True
    except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
      self.error_logger.info(f'error executing the command {command_str}')
      self.error_logger.info(f'error: {e}')
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def unsupported_os_message(self):
    print('this operating system is currently not supported.\n')
    self.info_logger.error('this operating system is currently not supported.')

    print('Exiting the program\n')
    self.info_logger.error('exiting the program')

    exit()

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_brew(self):
    """
    Check if Homebrew is installed and if not, install it.
    """
    if self.run_command("which brew"):
      return True

    print("Homebrew not found. Installing Homebrew...\n")
    self.info_logger.info("Homebrew not found. Installing Homebrew...")
    return self.run_command(
      "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_unzip(self, os_name):
    """
    Check if unzip is installed and if not, install it.
    """
    if self.run_command('unzip -v'):
      return True

    if os_name == 'linux':
      install_cmd = 'sudo apt install -y unzip'
    elif os_name == 'darwin':
      install_cmd = 'brew install unzip'
    else:
      return False

    return self.run_command(install_cmd)

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def manage_terraform(self, os_name, architecture):
    """
    Check if terraform is installed and if not, install it.
    """
    print('checking if terraform is installed.\n')

    terraform_cmd = 'terraform -v' if os_name == 'darwin' else '/usr/local/bin/terraform -v'

    if self.run_command(terraform_cmd):
      print('terraform is already installed.\n')
      return True

    print('installing terraform.\n')

    download_cmd = {
      ('linux',
       'aarch64'): 'curl -LO https://releases.hashicorp.com/terraform/1.4.2/terraform_1.4.2_linux_arm64.zip',
      ('darwin',
       'arm64'): 'curl -LO https://releases.hashicorp.com/terraform/1.4.2/terraform_1.4.2_darwin_arm64.zip'
    }.get((os_name, architecture))

    if not download_cmd:
      return False

    if (
      self.run_command(download_cmd) and self.run_command('unzip terraform_1.4.2_*_arm64.zip') and
      self.run_command('sudo mv terraform /usr/local/bin/') and
      self.run_command('sudo chmod +x /usr/local/bin/terraform') and
      self.run_command('/usr/local/bin/terraform -v')
    ):
      print("terraform successfully installed.\n")
      self.info_logger.info('terraform successfully installed.')
      return True
    else:
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_terraform(self):
    os_name = platform.system().lower()
    architecture = platform.machine().lower()
    supported = (os_name, architecture) in {('linux', 'aarch64'), ('darwin', 'arm64')}

    if not supported:
      self.unsupported_os_message()

    # Check and manage unzip
    if not self.check_and_install_unzip(os_name):
      print('unzip installation failed. exiting the program.\n')
      self.info_logger.error('unzip installation failed. exiting the program.')
      exit()

    # Check and manage terraform
    if self.manage_terraform(os_name, architecture):
      return True

    print('Terraform installation failed. exiting the program.\n')
    self.info_logger.error('Terraform installation failed. exiting the program.')
    return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_aws_cli(self):
    os_name = platform.system().lower()
    architecture = platform.machine().lower()
    supported = (os_name, architecture) in {('linux', 'x86_64'), ('linux', 'aarch64'), ('darwin', 'arm64')}

    if not supported:
      self.unsupported_os_message()

    print('checking if aws cli is installed.\n')
    self.info_logger.info('checking if aws cli is installed.')

    aws_cmd = 'aws --version'
    if self.run_command(aws_cmd):
      print("aws cli is already installed.\n")
      self.info_logger.info('aws cli is already installed.')
      return True

    print("installing aws cli.\n")
    self.info_logger.info('installing aws cli.')

    install_commands = {
      ('linux', 'x86_64'): [
        'curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip',
        'unzip awscliv2.zip',
        'sudo ./aws/install',
        'sudo chmod +x /usr/local/bin/aws',
        '/usr/local/bin/aws --version'
      ],
      ('linux', 'aarch64'): [
        'curl https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip -o awscliv2.zip',
        'unzip awscliv2.zip',
        'sudo ./aws/install',
        'sudo chmod +x /usr/local/bin/aws',
        '/usr/local/bin/aws --version'
      ],
      ('darwin', 'arm64'): [
        'curl https://awscli.amazonaws.com/AWSCLIV2.pkg -o AWSCLIV2.pkg',
        'sudo installer -pkg AWSCLIV2.pkg -target /'
      ]
    }

    if all(self.run_command(cmd) for cmd in install_commands[(os_name, architecture)]):
      print('aws cli installation successful.\n')
      self.info_logger.info('aws cli installation successful.')
      return True
    else:
      print('aws cli installation failed. exiting the program.\n')
      self.info_logger.error('aws cli installation failed. exiting the program.')
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_aws_iam_authenticator(self):
    print('checking if aws-iam-authenticator is already installed.\n')

    if shutil.which("aws-iam-authenticator"):
      print("aws-iam-authenticator is already installed.\n")
      self.info_logger.info('aws-iam-authenticator is already installed.')
      return True

    print("installing aws-iam-authenticator...\n")
    self.info_logger.info('installing aws-iam-authenticator...')

    os_name = platform.system().lower()
    architecture = platform.machine().lower()

    if (os_name, architecture) == ('linux', 'x86_64'):
      download_cmd = "curl -Lo aws-iam-authenticator https://github.com/kubernetes-sigs/aws-iam-authenticator" \
                     "/releases/download/v0.5.9/aws-iam-authenticator_0.5.9_linux_amd64"
    elif (os_name, architecture) == ('linux', 'aarch64'):
      download_cmd = "curl -Lo aws-iam-authenticator https://github.com/kubernetes-sigs/aws-iam-authenticator" \
                     "/releases/download/v0.5.9/aws-iam-authenticator_0.5.9_linux_arm64"
    elif (os_name, architecture) == ('darwin', 'arm64'):
      download_cmd = "curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/" \
                     "1.21.2/2021-07-05/bin/darwin/arm64/aws-iam-authenticator"
    else:
      print("Unsupported system:", os_name, architecture)
      self.info_logger.error("Unsupported system")
      return False

    chmod_cmd = "chmod +x ./aws-iam-authenticator"
    move_cmd = "sudo mv ./aws-iam-authenticator /usr/local/bin/"

    for cmd in [download_cmd, chmod_cmd, move_cmd]:
      if not self.run_command(cmd):
        return False

    print("aws-iam-authenticator installed successfully.\n")
    self.info_logger.info('aws-iam-authenticator installed successfully.')
    return True

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_helm(self):
    print('checking if helm is already installed.\n')

    if self.run_command("helm version --short"):
      print('helm is already installed.\n')
      return True

    print("helm not found, proceeding with installation.\n")
    self.info_logger.info("helm not found, proceeding with installation.")

    os_name = platform.system().lower()
    architecture = platform.machine().lower()

    if (os_name, architecture) == ('linux', 'aarch64') or (os_name, architecture) == ('darwin', 'arm64'):
      if (self.run_command(
        "curl -fsSL -o get_helm.sh "
        "https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3") and
        self.run_command("chmod 700 get_helm.sh") and
        self.run_command("./get_helm.sh")):
        print("helm installed successfully.\n")
        self.info_logger.info("helm installed successfully.")
        return True
      else:
        print("Error occurred during Helm installation.\n")
        self.error_logger.error("Error occurred during Helm installation.")
        return False
    else:
      print("Unsupported system:", os_name, architecture, "\n")
      self.info_logger.error("Unsupported system")
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def install_kubectl_linux(self):
    print("installing kubectl on linux...\n")
    self.info_logger.info("installing kubectl on linux...")

    commands = [
      "sudo apt-get update",
      "sudo apt-get install -y apt-transport-https ca-certificates curl",
      'sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg '
      'https://packages.cloud.google.com/apt/doc/apt-key.gpg',
      'echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] '
      'https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list',
      "sudo apt-get update",
      "sudo apt-get install -y kubectl"
    ]

    for command in commands:
      if not self.run_command(command):
        return False

    print("kubectl installed successfully.\n")
    self.info_logger.info("kubectl installed successfully.")
    return True

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def install_kubectl_macos(self):
    print("Installing kubectl on macOS...\n")
    self.info_logger.info("Installing kubectl on macOS...")

    # Install kubectl
    if self.run_command("brew install kubectl"):
      print("kubectl installed successfully.\n")
      self.info_logger.info("kubectl installed successfully.")
      return True
    else:
      print("kubectl installation failed.\n")
      self.info_logger.info("kubectl installation failed.")
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_and_install_kubectl(self):
    print('checking if kubectl is installed.\n')

    if not self.run_command("kubectl version --client --short"):
      print("kubectl not found.\n")
      self.error_logger.error("kubectl not found.")
      system = platform.system()

      if system == "Linux":
        return self.install_kubectl_linux()
      elif system == "Darwin":
        return self.install_kubectl_macos()
      else:
        print("Unsupported system:", system, "\n")
        self.error_logger.error("Unsupported system")
        sys.exit(1)
    else:
      print("kubectl is already installed:\n")
      self.info_logger.info("kubectl is already installed:")
      return True

  @staticmethod
  def fix_sources_list():
    """Comments out the invalid Docker repository in the sources.list file."""

    with open("/etc/apt/sources.list", "r") as file:
      lines = file.readlines()

    with open("/etc/apt/sources.list", "w") as file:
      for line in lines:
        if line.strip() == "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release stable -cs)":
          file.write("# " + line)
        else:
          file.write(line)

  def install_docker(self):
    """Installs Docker."""

    print("Installing Docker...")

    try:
      self.run_command("sudo apt-get install -y software-properties-common")
      self.run_command(
        "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -")
      ubuntu_version = subprocess.check_output("lsb_release -cs", shell=True, text=True).strip()
      self.run_command(
        f"sudo add-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu {ubuntu_version} stable'")
      self.run_command("sudo apt-get update")

      try:
        command = "sudo apt-get install -y docker-ce docker-ce-cli containerd.io"
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, check=True)
      except (subprocess.CalledProcessError, Exception) as _:
        print('Failed to start docker service. Trying to start it...')

        for attempt in range(60):
          try:
            command = "sudo systemctl start docker.service"
            subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, check=True)

            command = "sudo systemctl status docker.service"
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, check=True)

            status_output = process.stdout.decode()

            if "running" in status_output.lower():
              print("Docker service is now running.")
              break
          except (subprocess.CalledProcessError, Exception) as _:
            pass

          time.sleep(5)
        else:  # Will run if the loop completes normally (i.e., Docker failed to start after all attempts)
          print("Failed to start Docker service. Exiting the Program.")
          return False

      print("Docker installed successfully.")
      return True
    except subprocess.CalledProcessError as e:
      print(f"Error while installing Docker: {str(e)}")

  def check_and_install_docker(self):
    try:
      print("Checking if Docker is installed...")
      self.run_command("docker --version")

      print("Docker is already installed.")
    except subprocess.CalledProcessError:
      self.fix_sources_list()

      print("Docker is not installed. Starting Docker installation...")
      if self.install_docker():
        return True
