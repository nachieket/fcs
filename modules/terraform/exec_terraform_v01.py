import subprocess
import re

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class ExecTerraform:
    info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
    error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

    decorator = CustomDecorator(info_logger, error_logger)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def run_terraform_command(self, command, path):
        if command in ["plan", "apply", "destroy"]:
            command_list = ["/usr/local/bin/terraform", command, "-var-file=variables.tfvars"]
        else:
            command_list = ["/usr/local/bin/terraform", command]

        if command in ["init", "plan", "apply"]:
            command_list.append("-input=false")

        if command in ["apply", "destroy"]:
            command_list.append("-auto-approve")

        try:
            process = subprocess.Popen(
                command_list,
                cwd=path,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            for line in process.stdout:
                self.info_logger.info(line)

            process.wait()

            if process.returncode == 0:
                self.info_logger.info(f"{command.capitalize()} succeeded.")
                return process
            else:
                self.info_logger.info(f"{command.capitalize()} failed.")
                return False
        except (subprocess.SubprocessError, Exception) as e:
            self.error_logger.error(f'{e}')
            return False

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def should_apply_changes(self, path):
        command_list = ["/usr/local/bin/terraform", "plan", "-input=false", "-no-color"]

        process = subprocess.Popen(command_list, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout_lines = []
        while process.poll() is None:
            line = process.stdout.readline().strip()
            if line:
                stdout_lines.append(line)
                self.info_logger.info(line)

        _, stderr = process.communicate()

        if process.returncode != 0:
            print("#### Terraform plan failed ####\n")
            self.info_logger.info(stderr)
            return False

        stdout = "\n".join(stdout_lines)

        # Search for 'No changes.' in the output
        if "No changes." in stdout:
            self.info_logger.info('nochange')
            return 'nochange'

        # Search for 'Plan: X to add, Y to change, Z to destroy.' in the output
        match = re.search(r"Plan: (\d+) to add, (\d+) to change, (\d+) to destroy.", stdout)
        if match:
            to_add, to_change, to_destroy = map(int, match.groups())
            if to_add > 0 or to_change > 0 or to_destroy > 0:
                print("#### Changes detected. Applying changes. ####\n")
                return True

        print("#### No changes detected. Skipping apply. ####\n")
        return False
