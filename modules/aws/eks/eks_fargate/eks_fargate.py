import configparser
import json

from modules.terraform.exec_terraform import ExecTerraform
from modules.aws.aws_credentials.aws_credentials_check import AWSCredentialCheck
from modules.multithread.multithreading import MultiThreading
from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class EKSFargate:
  tf = ExecTerraform()

  info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
  error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

  decorator = CustomDecorator(info_logger, error_logger)

  @staticmethod
  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def read_config_file(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)

    terraform_variables = {key: config.get("terraform_variables", key) for key in
                           config.options("terraform_variables")}

    application_variables = {key: config.get("applications-to-install", key) for key in
                             config.options("applications-to-install")}

    return terraform_variables, application_variables

  @staticmethod
  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def write_variables_to_tfvars(terraform_variables, common_tags):
    with open("./aws/eks/eks_fargate/vars.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          tfvars_file.write(f'{key} = "{value}"\n')

      tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_aws_credentials(self):
    aws = AWSCredentialCheck()

    with MultiThreading() as mt:
      print('checking aws credentials\n')
      self.info_logger.info('checking aws credentials')

      if mt.run_with_progress_indicator(aws.check_aws_profile, 1):
        print('aws credentials exist under ~/.aws/credentials file\n')
        self.info_logger.info('aws credentials exist under ~/.aws/credentials file')
        return True
      else:
        print('aws credentials do not exist under ~/.aws/credentials file\n')
        self.error_logger.error('aws credentials do not exist under ~/.aws/credentials file')

        if not aws.accept_aws_values():
          return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def execute_terraform_command(self, command, path):
    messages = {
      'get': {
        'start': '#### executing "terraform get" ####\n',
        'success': '#### "terraform get" complete ####\n',
        'fail': '#### "terraform get" failed ####\n',
      },
      'init': {
        'start': '#### executing "terraform init" ####\n',
        'success': '#### "terraform init" complete ####\n',
        'fail': '#### "terraform init" failed ####\n',
      },
      'plan': {
        'start': '#### executing "terraform plan" ####\n',
        'success': '#### "terraform plan" complete ####\n',
        'fail': '#### "terraform plan" failed ####\n',
      },
      'apply': {
        'start': '#### executing "terraform apply" ####\n',
        'success': '#### "terraform apply" complete ####\n',
        'fail': '#### "terraform apply" failed ####\n',
      },
      'destroy': {
        'start': '#### executing "terraform destroy" ####\n',
        'success': '#### "terraform destroy" complete ####\n',
        'fail': '#### "terraform destroy" failed ####\n',
      },
    }

    with MultiThreading() as mt:
      print(messages[command]['start'])
      self.info_logger.info(messages[command]['start'])

      if mt.run_with_progress_indicator(self.tf.execute_terraform_command, 1, command, path):
        print(messages[command]['success'])
        self.info_logger.info(messages[command]['success'])
        return True
      else:
        print(messages[command]['fail'])
        self.error_logger.error(messages[command]['fail'])
        return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def create_eks_fargate_cluster(self, config_file):
    terraform_variables, application_variables = self.read_config_file(config_file)

    config = configparser.ConfigParser()
    config.read(config_file)

    common_tags = {key: config.get("terraform_variables:common_tags", key) for key in
                   config.options("terraform_variables:common_tags")}

    self.write_variables_to_tfvars(terraform_variables, common_tags)

    if (
      self.check_aws_credentials() and
      self.execute_terraform_command('get', './aws/eks/eks_fargate/') and
      self.execute_terraform_command('init', './aws/eks/eks_fargate/') and
      self.execute_terraform_command('apply', './aws/eks/eks_fargate/')
    ):
      return True
    else:
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def delete_eks_managed_node_cluster(self):
    if self.execute_terraform_command('destroy', './aws/eks/eks_managed_node/'):
      return True
    else:
      return False
