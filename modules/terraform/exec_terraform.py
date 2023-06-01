import subprocess

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class ExecTerraform:
  info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
  error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

  decorator = CustomDecorator(info_logger, error_logger)

  @staticmethod
  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def build_terraform_command_list(command):
    if command in ["plan", "apply", "destroy"]:
      command_list = ["/usr/local/bin/terraform", command, "-var-file=vars.tfvars"]
    else:
      command_list = ["/usr/local/bin/terraform", command]

    if command in ["init", "plan", "apply"]:
      command_list.append("-input=false")

    if command in ["apply", "destroy"]:
      command_list.append("-auto-approve")

    return command_list

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def execute_terraform_command(self, command, path):
    if command == "apply":
      if not self.should_apply_changes(path):
        return 'no-changes'

    command_list = self.build_terraform_command_list(command)

    try:
      process = subprocess.Popen(
        command_list,
        cwd=path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
      )

      stdout, stderr = process.communicate()

      for line in stdout.splitlines():
        self.info_logger.info(line)

      if process.returncode == 0:
        self.info_logger.info(f"{command.capitalize()} succeeded.")
        return process
      else:
        self.info_logger.info(f"{command.capitalize()} failed.")
        return False
    except (subprocess.SubprocessError, Exception) as e:
      self.error_logger.error(f'{e}')
      return False

  def should_apply_changes(self, path):
    command_list = self.build_terraform_command_list("plan")
    process = subprocess.Popen(command_list, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
      print("terraform plan failed\n")

      self.error_logger.error("terraform plan failed")
      self.error_logger.error(stderr)

      return False

    # Search for 'No changes.' in the output
    if "No changes." in stdout:
      self.info_logger.info('nochange')
      return False

    # Find the line containing "Plan:"
    plan_line = [line for line in stdout.split('\n') if "Plan:" in line]

    if plan_line:
      # Extract numbers from the plan_line
      to_add, to_change, to_destroy = [int(num) for num in plan_line[0].split() if num.isdigit()]

      if to_add > 0 or to_change > 0 or to_destroy > 0:
        print("\n\nchanges detected. applying changes.\n")
        self.info_logger.info("changes detected. applying changes.")
        return True

    print('\n\nNo changes detected. Skipping apply')
    self.info_logger.info("no changes detected. Skipping apply")
    return False
