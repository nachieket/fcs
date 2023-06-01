import json
import subprocess

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class HelmOperations:
    info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
    error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

    decorator = CustomDecorator(info_logger, error_logger)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def helm_list_all_namespaces(self):
        """Executes the `helm list --all-namespaces -o json` command and returns the output."""
        output = subprocess.check_output(["helm", "list", "--all-namespaces", "-o", "json"]).decode("utf-8")
        self.info_logger.info(output)

        return json.loads(output)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def check_helm_chart_exists(self, chart_name, namespace):
        """Checks if the helm chart `chart_name` exists in the `namespace` namespace."""
        for chart in self.helm_list_all_namespaces():
            if chart["name"] == chart_name and chart["namespace"] == namespace:
                return True
        return False

    @staticmethod
    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def delete_helm_chart(chart_name, namespace):
        """Deletes the helm chart `chart_name` in the `namespace` namespace."""
        helm_uninstall = subprocess.run(
            ["helm", "uninstall", chart_name, "--namespace", namespace],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        stdout = helm_uninstall.stdout if helm_uninstall.stdout else None
        stderr = helm_uninstall.stderr if helm_uninstall.stderr else None

        return stdout, stderr

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def check_and_delete_helm_chart(self, chart_name, namespace):
        """Checks if the helm chart `chart_name` exists in the `namespace` namespace and deletes it if it does."""

        if self.check_helm_chart_exists(chart_name, namespace):
            stdout, stderr = self.delete_helm_chart(chart_name, namespace)
            if stdout:
                self.info_logger.info(stdout)
                if 'release "{}" uninstalled'.format(chart_name) in stdout:
                    print('helm chart {} uninstalled successfully'.format(chart_name))
            if stderr:
                self.error_logger.error(stderr)
        else:
            print("helm chart {} doesn't exist under {} namespace. nothing to do.\n".format(chart_name, namespace))
