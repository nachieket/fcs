import subprocess

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class KPA:
    info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
    error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

    decorator = CustomDecorator(info_logger, error_logger)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def __init__(self, config_file_path = "./aws/eks/eks_managed_node/config_value.yaml"):
        self.add_helm_repo_cmd = ["helm", "repo", "add", "kpagent-helm", "https://registry.crowdstrike.com/kpagent-helm"]
        self.update_helm_repo_cmd = ["helm", "repo", "update"]
        self.config_file_path = config_file_path
        self.helm_upgrade_install_cmd = [
            "helm", "upgrade", "--install",
            "-f", self.config_file_path,
            "--create-namespace",
            "-n", "falcon-kubernetes-protection",
            "kpagent", "kpagent-helm/cs-k8s-protection-agent",
        ]

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def deploy_kpa(self):
        try:
            add_helm_repo = subprocess.run(self.add_helm_repo_cmd, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, check=True)

            if add_helm_repo.stdout:
                self.info_logger.info(add_helm_repo.stdout)
            if add_helm_repo.stderr:
                self.error_logger.error(add_helm_repo.stderr)

            update_helm_repo = subprocess.run(self.update_helm_repo_cmd, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, check=True)

            if update_helm_repo.stdout:
                self.info_logger.info(update_helm_repo.stdout)
            if update_helm_repo.stderr:
                self.error_logger.error(update_helm_repo.stderr)

            print('helm repo added and updated successfully\n')
            self.info_logger.info('helm repo added and updated Successfully')
        except subprocess.CalledProcessError as e:
            print(f"error: {e}. failed to add and update helm repo.")
            self.error_logger.error(f"error: {e}. failed to add and update helm repo.")
            return False

        try:
            helm_install = subprocess.run(self.helm_upgrade_install_cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, check=True)

            if helm_install.stdout:
                self.info_logger.info(helm_install.stdout)
            if helm_install.stderr:
                self.error_logger.error(helm_install.stderr)

            self.info_logger.info('kpa installation successful')

            return True
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}. failed to run helm upgrade --install command.")
            self.error_logger.error(f"Error: {e}. failed to run helm upgrade --install command.")

            return False
