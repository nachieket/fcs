import os
import argparse

from modules.decorators.decorators import CustomDecorator
from modules.logging.logging import CustomLogger


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        # Get the default action invocation formatting
        default = super()._format_action_invocation(action)

        # Add extra spacing for readability
        return default.ljust(45)

    def _format_action(self, action):
        # Get the default help text for this action
        help_text = super()._format_action(action)

        # Remove the newline character and extra space after the action invocation
        help_text = help_text.replace("\n", "").replace("  ", " ", 1)

        # Add a newline character at the end of the help text
        help_text += "\n"

        return help_text


class CustomParser:
    info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
    error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

    decorator = CustomDecorator(info_logger, error_logger)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            usage='fcs.py [-h] \n'
                  '\nAWS Usage:\n\n'
                  '{--create | --delete} {--eks-managed-node | --eks-fargate | --eks-bottlerocket} '
                  '[--cluster-config-file <cluster_config_file>] [--install-falcon-sensor-daemonset | '
                  '--install-falcon-sensor-sidecar | --install-falcon-sensor-os-agent] '
                  '[--install-kpa --kpa-config-file <kpa_config_file>] [--install-detections-container] '
                  '[--falcon-client-id <falcon_client_id> --falcon-client-secret <falcon_client_secret> '
                  '--falcon-cid <falcon_cid> --falcon-cloud-region <falcon_cloud_region> '
                  '--falcon-cloud-api <falcon_cloud_api>]', formatter_class=CustomHelpFormatter
        )

        self.configure_parser()
        self.args = self.parser.parse_args()
        self.validate_args()
        # self.parser.print_help()

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def configure_parser(self):
        aws_group = self.parser.add_argument_group('AWS')

        action_group = aws_group.add_mutually_exclusive_group(required=True)
        action_group.add_argument('--create', action='store_true', help='Create an AWS EKS managed node cluster')
        action_group.add_argument('--delete', action='store_true', help='Delete an AWS EKS managed node cluster')

        aws_cluster_group = aws_group.add_mutually_exclusive_group(required=True)
        aws_cluster_group.add_argument('--eks-managed-node', action='store_true', help='Select an AWS EKS managed node cluster')
        aws_cluster_group.add_argument('--eks-fargate', action='store_true', help='Select an AWS EKS Fargate cluster')
        aws_cluster_group.add_argument('--eks-bottlerocket', action='store_true', help='Select an AWS EKS Bottlerocket cluster')

        aws_cluster_config_file = aws_group.add_mutually_exclusive_group(required=False)
        aws_cluster_config_file.add_argument('--cluster-config-file', type=str, help='Configuration file for the AWS cluster')

        falcon_sensor_group = aws_group.add_mutually_exclusive_group(required=False)
        falcon_sensor_group.add_argument('--install-falcon-sensor-daemonset', action='store_true',
                                         help='Install Falcon Sensor in Daemonset Mode')
        falcon_sensor_group.add_argument('--install-falcon-sensor-sidecar', action='store_true',
                                         help='Install Falcon Sensor in Sidecar Mode')
        falcon_sensor_group.add_argument('--install-falcon-sensor-os-agent', action='store_true',
                                         help='Install Falcon Sensor in Host Agent Mode')

        kpa = aws_group.add_mutually_exclusive_group(required=False)
        kpa.add_argument('--install-kpa', action='store_true', help='Install Kubernetes Protection Agent')

        aws_group.add_argument('--kpa-config-file', type=str, help='KPA Configuration File')

        detections_container = aws_group.add_mutually_exclusive_group(required=False)
        detections_container.add_argument('--install-detections-container', action='store_true', help='Install Detections Container')

        aws_group.add_argument('--falcon-client-id', type=str, help='Falcon Client ID')
        aws_group.add_argument('--falcon-client-secret', type=str, help='Falcon Client Secret')
        aws_group.add_argument('--falcon-cid', type=str, help='Falcon Customer ID')
        aws_group.add_argument('--falcon-cloud-region', type=str, help='Falcon Cloud Region')
        aws_group.add_argument('--falcon-cloud-api', type=str, help='Falcon Cloud API')

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def validate_args(self):
        conditions_errors = [
            (self.args.cluster_config_file and not os.path.isfile(self.args.cluster_config_file),
             f"File '{self.args.cluster_config_file}' does not exist"),

            (self.args.cluster_config_file and not (
                        self.args.eks_managed_node or self.args.eks_fargate or self.args.eks_bottlerocket),
             "--file can only be used with --eks-managed-node or --eks-fargate or --eks-bottlerocket"),

            (self.args.install_falcon_sensor_daemonset and (self.args.eks_fargate or self.args.eks_bottlerocket),
             "--install-falcon-sensor-daemonset cannot be set with EKS Fargate or EKS Bottlerocket"),

            (self.args.install_falcon_sensor_sidecar and self.args.eks_managed_node,
             "--install-falcon-sensor-sidecar cannot be set with EKS Managed Node Cluster"),

            (self.args.install_falcon_sensor_os_agent and (self.args.eks_fargate or self.args.eks_bottlerocket),
             "--install-falcon-sensor-os-agent cannot be set with EKS Fargate or EKS Bottlerocket"),

            ((self.args.install_falcon_sensor_daemonset or self.args.install_falcon_sensor_sidecar) and not (
                    self.args.falcon_client_id and self.args.falcon_client_secret and self.args.falcon_cid
                    and self.args.falcon_cloud_region and self.args.falcon_cloud_api),
             "--install-falcon-sensor-daemonset and --install-falcon-sensor-sidecar require --falcon-client-id, "
             "--falcon-client-secret, --falcon-cid, --falcon-cloud-region and --falcon-cloud-api"),

            ((self.args.falcon_client_id or self.args.falcon_client_secret or self.args.falcon_cid or
              self.args.falcon_cloud_region or self.args.falcon_cloud_api)
             and not (self.args.install_falcon_sensor_daemonset or self.args.install_falcon_sensor_sidecar),
             "--falcon-client-id, --falcon-client-secret --falcon-cid, --falcon-cloud-region and --falcon-cloud-api "
             "require --install-falcon-sensor-daemonset or --install-falcon-sensor-sidecar"),

            (self.args.install_kpa and not self.args.kpa_config_file,
             "--install-kpa requires --kpa-config-file")
        ]

        for condition, error_msg in conditions_errors:
            if condition:
                self.parser.error(error_msg)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def run(self):
        # EKS Managed Node
        parameters = {}

        if self.args.create:
            parameters['action'] = 'create'

        if self.args.eks_managed_node:
            parameters['cloud'] = 'aws'
            parameters['region'] = 'eu-west-2'
            parameters['cluster_name'] = 'eks_development_cluster'
            parameters['cluster'] = 'eks_managed_node'
        elif self.args.eks_fargate:
            parameters['cloud'] = 'aws'
            parameters['cluster'] = 'eks_fargate'
        elif self.args.eks_bottlerocket:
            parameters['cloud'] = 'aws'
            parameters['cluster'] = 'eks_bottlerocket'

        if self.args.cluster_config_file:
            parameters['cluster_config_file'] = self.args.cluster_config_file
        else:
            parameters['cluster_config_file'] = 'default-config'

        if self.args.install_falcon_sensor_daemonset \
            and self.args.falcon_client_id and self.args.falcon_client_secret and self.args.falcon_cid \
                and self.args.falcon_cloud_region and self.args.falcon_cloud_api:

            parameters['sensor_type'] = 'daemonset'
            parameters['falcon_client_id'] = self.args.falcon_client_id
            parameters['falcon_client_secret'] = self.args.falcon_client_secret
            parameters['falcon_client_cid'] = self.args.falcon_cid
            parameters['falcon_cloud_region'] = self.args.falcon_cloud_region
            parameters['falcon_cloud_api'] = self.args.falcon_cloud_api
        elif self.args.install_falcon_sensor_sidecar \
                and self.args.falcon_client_id and self.args.falcon_client_secret and self.args.falcon_cid \
                and self.args.falcon_cloud_region and self.args.falcon_cloud_api:

            parameters['sensor_type'] = 'sidecar'
            parameters['falcon_client_id'] = self.args.falcon_client_id
            parameters['falcon_client_secret'] = self.args.falcon_client_secret
            parameters['falcon_client_cid'] = self.args.falcon_cid
            parameters['falcon_cloud_region'] = self.args.falcon_cloud_region
            parameters['falcon_cloud_api'] = self.args.falcon_cloud_api

        if self.args.install_kpa and self.args.kpa_config_file:
            parameters['kpa-status'] = 'install-kpa'
            parameters['kpa-config-file'] = self.args.kpa_config_file

        if self.args.install_detections_container:
            parameters['detections-container'] = 'install-detection-container'

        return parameters
