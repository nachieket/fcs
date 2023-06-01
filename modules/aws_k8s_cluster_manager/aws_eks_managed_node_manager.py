import subprocess
import configparser

from modules.aws.eks.eks_managed_node.eks_managed_node import EKSManagedNode
from modules.vendors.security.crowdstrike.sensors.daemonset.fs_daemonset import FalconSensorDaemonset
from modules.vendors.security.crowdstrike.sensors.kpa.kpa import KPA
from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator
from modules.helm.helm_operations import HelmOperations


class AWSEKSClusterManager:
    info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
    error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

    decorator = CustomDecorator(info_logger, error_logger)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def create_eks_managed_node(self, config_file='conf/aws/eks/eks-managed-node.config'):
        eks = EKSManagedNode()
        if eks.create_eks_managed_node_cluster(config_file):
            print('aws eks managed node cluster build successful\n')
            self.info_logger.info('aws eks managed node cluster build successful')
            return True
        else:
            print('aws eks managed node cluster build failed\n')
            self.error_logger.error('aws eks managed node cluster build failed')
            return False

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def delete_eks_managed_node(self):
        helm = HelmOperations()

        # checks if the helm charts `falcon-helm` and `kpagent` exist and deletes them if they do
        helm.check_and_delete_helm_chart("falcon-helm", "falcon-system")
        helm.check_and_delete_helm_chart("kpagent", "falcon-kubernetes-protection")

        eks = EKSManagedNode()

        # delete eks managed node cluster
        if eks.delete_eks_managed_node_cluster():
            print('aws eks managed node cluster delete successful\n')
            self.info_logger.info('aws eks managed node cluster delete successful')
        else:
            print('aws eks managed node cluster delete failed\n')
            self.error_logger.error('aws eks managed node cluster delete failed')

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def install_falcon_sensor_daemonset(self, parameters):
        if 'sensor_type' in parameters and parameters['sensor_type'] == 'daemonset':
            daemonset = FalconSensorDaemonset(
                falcon_client_id=parameters['falcon_client_id'],
                falcon_client_secret=parameters['falcon_client_secret'],
                falcon_cid=parameters['falcon_client_cid'],
                falcon_cloud_region=parameters['falcon_cloud_region'],
                falcon_cloud_api=parameters['falcon_cloud_api']
            )

            print('starting falcon sensor installation\n')
            self.info_logger.info('starting falcon sensor installation')

            if daemonset.deploy_falcon_sensor_daemonset():
                print('\nfalcon sensor installation successful\n')
                self.info_logger.info('falcon sensor installation successful')
            else:
                print('falcon sensor installation failed\n')
                self.error_logger.error('falcon sensor installation failed')

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def install_kpa(self, parameters):
        if 'kpa-status' in parameters and parameters['kpa-status'] == 'install-kpa':
            kpa = KPA('/tmp/config_value.yaml')

            if kpa.deploy_kpa():
                print('kubernetes protection agent installation successful\n')
                self.info_logger.info('kubernetes protection agent installation successful')
            else:
                print('kubernetes protection agent installation failed\n')
                self.error_logger.error('kubernetes protection agent installation failed')

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def update_eks_kubeconfig(self, region, cluster_name):
        try:
            command = ["aws", "eks", "update-kubeconfig", "--region", region, "--name", cluster_name]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            stdout, stderr = process.communicate()

            if process.returncode == 0:
                print("Kubeconfig updated successfully.\n")
                self.info_logger.info("Kubeconfig updated successfully.")
                self.info_logger.info(stdout.strip())
                return stdout.strip()
            else:
                print("Error updating kubeconfig:")
                self.error_logger.error("Error updating kubeconfig:")
                print(stderr)
                self.error_logger.error(stderr)
                return None
        except Exception as e:
            print("Error executing command:", e)
            self.error_logger.error("Error executing command:", e)
            return None

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

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def start_eks_managed_node_operations(self, parameters):
        config_file = (
            './conf/aws/eks/eks-managed-node.config'
            if parameters['cluster_config_file'] == 'default-config'
            else parameters['cluster_config_file']
        )

        terraform_variables, application_variables = self.read_config_file(config_file)

        if (
                parameters['cloud'] == 'aws'
                and parameters['action'] == 'create'
                and parameters['cluster'] == 'eks_managed_node'
                and self.create_eks_managed_node(config_file)
        ):
            output = self.update_eks_kubeconfig(
                terraform_variables['region'], terraform_variables['cluster_name']
            )
            if output:
                print("Output:", output, "\n")

                self.install_falcon_sensor_daemonset(parameters)
                self.install_kpa(parameters)
            else:
                self.error_logger.error('installation of falcon sensor and kpa failed because kubeconfig '
                                        'could not be updated')
        elif (
                parameters['cloud'] == 'aws'
                and parameters['action'] == 'delete'
                and parameters['cluster'] == 'eks_managed_node'
        ):
            self.delete_eks_managed_node()
