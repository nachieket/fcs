import os
import platform

from modules.system_check.system_check import SystemCheck
from modules.custom_parser.custom_parser import CustomParser
from modules.aws_k8s_cluster_manager.aws_eks_managed_node_manager import AWSEKSClusterManager
from modules.aws_k8s_cluster_manager.aws_eks_fargate_manager import AWSFargateClusterManager
from modules.aws.ecs.ecs_fargate.ecs_fargate import AWSECSClusterManager
from modules.aws.aws_credentials.aws_credentials_check import AWSCredentialCheck

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator

info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

decorator = CustomDecorator(info_logger, error_logger)


@decorator.standard_func_logger
@decorator.standard_func_timer
def add_usr_local_bin_to_path():
  export_line = 'export PATH="/usr/local/bin:$PATH"'

  # Read ~/.bashrc
  bashrc_path = os.path.expanduser('~/.bashrc')
  with open(bashrc_path, 'r') as bashrc:
    bashrc_content = bashrc.read()

  # Check if export line is already in the file
  if export_line not in bashrc_content:
    # Update the ~/.bashrc file with the new PATH
    with open(bashrc_path, 'a') as bashrc:
      bashrc.write(f'\n{export_line}\n')
      info_logger.info('Added export PATH="/usr/local/bin:$PATH" to ~/.bashrc')


@decorator.standard_func_logger
@decorator.standard_func_timer
def check_and_add_eks_tools():
  print('\n###################################')
  print('### Check and Install EKS Tools ###')
  print('###################################\n')
  system = SystemCheck()

  os_name = platform.system().lower()

  if os_name == 'darwin':
    if not system.check_and_install_brew():
      print("Failed to install Homebrew. Exiting the program.\n")
      system.info_logger.error("Failed to install Homebrew. Exiting the program.")
      return False

  if (
    system.check_and_install_terraform() and system.check_and_install_aws_cli() and
    system.check_and_install_aws_iam_authenticator() and system.check_and_install_helm() and
    system.check_and_install_kubectl()
  ):
    return True
  else:
    return False


@decorator.standard_func_logger
@decorator.standard_func_timer
def check_and_add_ecs_tools():
  print('\n###################################')
  print('### Check and Install ECS Tools ###')
  print('###################################\n')
  system = SystemCheck()

  os_name = platform.system().lower()

  if os_name == 'darwin':
    print('You are running this program on MacOS, which is not supported with this option.')
    return False

  if (
    system.check_and_install_aws_cli() and system.check_and_install_aws_iam_authenticator()
    and system.check_and_install_docker()
  ):
    return True
  else:
    return False


@decorator.standard_func_logger
@decorator.standard_func_timer
def main():
  # Reload the ~/.bashrc file to apply the changes immediately
  # subprocess.run(['bash', '-c', 'source ~/.bashrc'])

  # # Parse the runtime parameters
  parser = CustomParser()
  options = parser.run()

  # Add /usr/local/bin to ~/.bashrc
  add_usr_local_bin_to_path()

  if options['cloud'] == 'aws':
    if options['cluster'] == 'eks_managed_node' or options['cluster'] == 'eks_fargate':
      # console print message
      if options['action'] == 'create':
        if not check_and_add_eks_tools():
          print('check and/or installation of system tools failed. exiting the program.')
          exit()

        print('#####################')
        print('### cluster build ###')
        print('#####################\n')
      elif options['action'] == 'delete':
        print('#######################')
        print('### cluster removal ###')
        print('#######################\n')

      # pass runtime parameters to build k8s cluster
      if options['cluster'] == 'eks_managed_node':
        eks_managed_node = AWSEKSClusterManager()
        eks_managed_node.start_eks_managed_node_operations(options)
      elif options['cluster'] == 'eks_fargate':
        eks_fargate = AWSFargateClusterManager()
        eks_fargate.start_eks_fargate_operations(options)
    elif options['cluster'] == 'ecs_fargate':
      check_and_add_ecs_tools()

      aws = AWSCredentialCheck()
      aws.check_and_accept_aws_credentials()

      ecs = AWSECSClusterManager()
      ecs.start_ecs_cluster_operations(options)
  elif options[0] == 'azure':
    pass
  elif options[0] == 'gcp':
    pass

  print('\nUse "source ~/.bashrc" to include /usr/local/bin to the $PATH variable\n')
