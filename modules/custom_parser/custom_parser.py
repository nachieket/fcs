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
            '[{--create | --delete} {--eks-managed-node | --eks-fargate | --eks-bottlerocket} '
            '[--cluster-config-file <cluster_config_file>]] [{--install-falcon-sensor-daemonset | '
            '--install-falcon-sensor-sidecar} {--falcon-client-id <falcon_client_id> '
            '--falcon-client-secret <falcon_client_secret> '
            '--falcon-cid <falcon_cid> --falcon-cloud-region <falcon_cloud_region> '
            '--falcon-cloud-api <falcon_cloud_api>}] '
            '[--install-kpa --kpa-config-file <kpa_config_file>] [--install-detections-container] ',
      formatter_class=CustomHelpFormatter
    )

    self.configure_parser()
    self.args = self.parser.parse_args()
    self.validate_args()
    # self.parser.print_help()

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def configure_parser(self):
    aws_group = self.parser.add_argument_group('AWS')

    action_group = aws_group.add_mutually_exclusive_group(required=False)
    action_group.add_argument('--create', action='store_true', help='Create an AWS Cluster')
    action_group.add_argument('--delete', action='store_true', help='Delete an AWS Cluster')

    aws_cluster_group = aws_group.add_mutually_exclusive_group(required=False)
    aws_cluster_group.add_argument('--eks-managed-node', action='store_true',
                                   help='Select an AWS EKS Managed Node Cluster')
    aws_cluster_group.add_argument('--eks-fargate', action='store_true',
                                   help='Select an AWS EKS Fargate Cluster')
    aws_cluster_group.add_argument('--eks-bottlerocket', action='store_true',
                                   help='Select an AWS EKS Bottlerocket Cluster')

    aws_cluster_config_file = aws_group.add_mutually_exclusive_group(required=False)
    aws_cluster_config_file.add_argument('--cluster-config-file', type=str,
                                         help='Configuration file for the AWS Cluster')

    ecs_fargate = self.parser.add_argument_group('AWS ECS FARGATE')

    ecs_fargate.add_argument('--ecs-fargate', action='store_true', help='Operate on AWS ECS Fargate Service')
    ecs_fargate.add_argument('--patch-definitions', action='store_true', help='Patch AWS ECS Fargate Definitions')
    ecs_fargate.add_argument('--register-definitions', action='store_true', help='Register AWS ECS Fargate Definitions')
    ecs_fargate.add_argument('--launch-new-tasks', action='store_true', help='Run New AWS ECS Fargate Definition Tasks')
    ecs_fargate.add_argument('--stop-previous-tasks', action='store_true', help='Remove Old AWS ECS Fargate '
                                                                                'Definition Tasks')
    ecs_fargate.add_argument('--ecs-config-file', type=str, help='ECS Configuration File')
    ecs_fargate.add_argument('--ecs-falcon-cid', type=str, help='ECS CrowdStrike Falcon CID')
    ecs_fargate.add_argument('--ecs-image-uri', type=str, help='AWS Repository')

    sensor_group = self.parser.add_argument_group('FALCON SENSOR')

    falcon_sensor_group = sensor_group.add_mutually_exclusive_group(required=False)
    falcon_sensor_group.add_argument('--install-falcon-sensor-daemonset', action='store_true',
                                     help='Install Falcon Sensor in Daemonset Mode')
    falcon_sensor_group.add_argument('--install-falcon-sensor-sidecar', action='store_true',
                                     help='Install Falcon Sensor in Sidecar Mode')
    # falcon_sensor_group.add_argument('--install-falcon-sensor-os-agent', action='store_true',
    #                                  help='Install Falcon Sensor in Host Agent Mode')

    sensor_group.add_argument('--falcon-client-id', type=str, help='Falcon Client ID')
    sensor_group.add_argument('--falcon-client-secret', type=str, help='Falcon Client Secret')
    sensor_group.add_argument('--falcon-cid', type=str, help='Falcon Customer ID')
    sensor_group.add_argument('--falcon-cloud-region', type=str, help='Falcon Cloud Region')
    sensor_group.add_argument('--falcon-cloud-api', type=str, help='Falcon Cloud API')

    kpa_group = self.parser.add_argument_group('KUBERNETES PROTECTION AGENT')

    kpa_agent = kpa_group.add_mutually_exclusive_group(required=False)
    kpa_agent.add_argument('--install-kpa', action='store_true', help='Install Kubernetes Protection Agent')

    kpa_group.add_argument('--kpa-config-file', type=str, help='KPA Configuration File')

    detection_container_group = self.parser.add_argument_group('DETECTIONS CONTAINER')

    detections_container = detection_container_group.add_mutually_exclusive_group(required=False)
    detections_container.add_argument('--install-detections-container', action='store_true',
                                      help='Install Detections Container')

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def validate_args(self):
    eks_errors = [
      ((self.args.create or self.args.delete) and not (
        self.args.eks_managed_node or self.args.eks_fargate or self.args.eks_bottlerocket),
       "--create or --delete can only be used with --eks-managed-node or --eks-fargate or --eks-bottlerocket"),

      (self.args.cluster_config_file and not os.path.isfile(self.args.cluster_config_file),
       f"File '{self.args.cluster_config_file}' does not exist"),

      ((self.args.create or self.args.delete) and (
        self.args.eks_managed_node or self.args.eks_fargate or self.args.eks_bottlerocket) and (
         self.args.ecs_fargate or self.args.patch_definitions or self.args.register_definitions
         or self.args.launch_new_tasks or self.args.stop_previous_tasks),
       "--create/--delete --eks-managed-node/--eks-fargate/--eks-bottlerocket cannot be used with "
       "--ecs-fargate options"),

      (self.args.cluster_config_file and not (
        self.args.eks_managed_node or self.args.eks_fargate or self.args.eks_bottlerocket),
       "--file can only be used with --eks-managed-node or --eks-fargate or --eks-bottlerocket"),

      (((self.args.patch_definitions or self.args.register_definitions or self.args.launch_new_tasks
         or self.args.stop_previous_tasks)
        or (self.args.patch_definitions and self.args.register_definitions and self.args.launch_new_tasks
            and self.args.stop_previous_tasks))
       and (self.args.install_falcon_sensor_daemonset or self.args.install_falcon_sensor_sidecar
            or self.args.install_kpa or self.args.install_detections_container),
       "--install-falcon-sensor-daemonset, --install-falcon-sensor-sidecar, --install-kpa, and "
       "--install-detections-container options cannot be used with --ecs-fargate option"),

      (self.args.install_falcon_sensor_daemonset and (self.args.eks_fargate or self.args.eks_bottlerocket),
       "--install-falcon-sensor-daemonset cannot be set with EKS Fargate or EKS Bottlerocket"),

      (self.args.install_falcon_sensor_sidecar and self.args.eks_managed_node,
       "--install-falcon-sensor-sidecar cannot be set with EKS Managed Node Cluster"),

      # (self.args.install_falcon_sensor_os_agent and (self.args.eks_fargate or self.args.eks_bottlerocket),
      #  "--install-falcon-sensor-os-agent cannot be set with EKS Fargate or EKS Bottlerocket"),

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

    ecs_errors = [
      (self.args.ecs_fargate and not (self.args.patch_definitions or self.args.register_definitions or
                                      self.args.launch_new_tasks or self.args.stop_previous_tasks),
       "--ecs-fargate requires parameters in this order --patch-definitions "
       "--register-definitions --launch-new-tasks --stop-previous-tasks"),

      ((self.args.ecs_fargate and self.args.patch_definitions) and not (
        self.args.ecs_falcon_cid and self.args.ecs_image_uri),
       "--ecs-falcon-cid and --ecs-image-uri are required"),

      ((self.args.ecs_fargate and self.args.patch_definitions) and (
        self.args.register_definitions or self.args.launch_new_tasks or self.args.stop_previous_tasks) and not (
        self.args.ecs_falcon_cid and self.args.ecs_image_uri
      ),
       "--ecs-falcon-cid and --ecs-image-uri are required"),

      (((self.args.ecs_fargate and self.args.patch_definitions and not self.args.register_definitions) and
        (self.args.launch_new_tasks or self.args.stop_previous_tasks)),
       "--launch-new-tasks or --stop-previous-tasks cannot be passed without --patch-definitions --register-definitions"),

      (((self.args.ecs_fargate and self.args.register_definitions) and not self.args.patch_definitions),
       "--register-definitions cannot be passed without --patch-definitions"),

      (((self.args.ecs_fargate and self.args.register_definitions and (
        self.args.launch_new_tasks or self.args.stop_previous_tasks)) and not self.args.patch_definitions),
       "--register-definitions cannot be passed without --patch-definitions"),

      (((self.args.ecs_fargate and (self.args.register_definitions or self.args.launch_new_tasks
                                    or self.args.stop_previous_tasks)) and not self.args.patch_definitions),
       "the supported order of options is --patch-definitions --register-definitions "
       "--launch-new-tasks --stop-previous-tasks"),

      (((self.args.ecs_fargate and self.args.launch_new_tasks
         ) and not (self.args.patch_definitions and self.args.register_definitions)),
       "--launch-new-tasks cannot be passed without --patch-definitions --register-definitions"),

      ((self.args.ecs_fargate and self.args.patch_definitions and self.args.register_definitions
        and self.args.stop_previous_tasks) and not self.args.launch_new_tasks,
       "--stop-previous-tasks cannot be passed without --launch-new-tasks"),

      (((self.args.patch_definitions or self.args.register_definitions or self.args.launch_new_tasks
         or self.args.stop_previous_tasks) and not self.args.ecs_fargate),
       "--patch-definitions --register-definitions --launch-new-tasks --stop-previous-tasks "
       "cannot be used without --ecs-fargate")
    ]

    conditions_errors = eks_errors + ecs_errors

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
    elif self.args.delete:
      parameters['action'] = 'delete'

    if self.args.eks_managed_node or self.args.eks_fargate or self.args.eks_bottlerocket:
      parameters['cloud'] = 'aws'

      if self.args.eks_managed_node:
        parameters['cluster'] = 'eks_managed_node'
      elif self.args.eks_fargate:
        parameters['cluster'] = 'eks_fargate'
      elif self.args.eks_bottlerocket:
        parameters['cluster'] = 'eks_bottlerocket'

      parameters[
        'cluster_config_file'] = self.args.cluster_config_file if self.args.cluster_config_file else 'default-config'

    if self.args.install_falcon_sensor_daemonset and self.args.falcon_client_id and self.args.falcon_client_secret \
      and self.args.falcon_cid and self.args.falcon_cloud_region and self.args.falcon_cloud_api:

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

    if self.args.ecs_fargate:
      parameters.update({
        'cloud': 'aws',
        'cluster': 'ecs_fargate',
        'ecs_patch_definitions': 'yes' if self.args.patch_definitions else 'no',
        'ecs_register_definitions': 'yes' if self.args.register_definitions else 'no',
        'ecs_launch_new_tasks': 'yes' if self.args.launch_new_tasks else 'no',
        'ecs_stop_previous_tasks': 'yes' if self.args.stop_previous_tasks else 'no',
        'ecs_config_file': self.args.ecs_config_file if self.args.ecs_config_file else None,
        'ecs_falcon_cid': self.args.ecs_falcon_cid if self.args.ecs_falcon_cid else None,
        'ecs_image_uri': self.args.ecs_image_uri if self.args.ecs_image_uri else None
      })

    return parameters
