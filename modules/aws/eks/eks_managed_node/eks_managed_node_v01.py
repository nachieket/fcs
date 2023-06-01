import configparser
import json

from modules.terraform.exec_terraform import ExecTerraform
from modules.aws.aws_credentials.aws_credentials_check import AWSCredentialCheck
from modules.multithread.multithreading import MultiThreading
# from modules.decorators.decorators import CustomDecorator


class EKSManagedNode:
    tf = ExecTerraform()
    # decorator = CustomDecorator('/tmp/crowdstrike/system_logs/info.log', '/tmp/crowdstrike/system_logs/error.log')
    #
    # @decorator.func_logger
    # @decorator.func_timer

    @staticmethod
    def read_config_file(file_path):
        config = configparser.ConfigParser()
        config.read(file_path)

        terraform_variables = {key: config.get("terraform_variables", key) for key in
                               config.options("terraform_variables")}
        # crowdstrike_variables = {key: config.get("crowdstrike", key) for key in config.options("crowdstrike")}
        application_variables = {key: config.get("applications-to-install", key) for key in config.options("applications-to-install")}

        return terraform_variables, application_variables

    @staticmethod
    def write_variables_to_tfvars(terraform_variables, common_tags, eks_managed_node_groups):
        with open("./aws/eks/eks_managed_node/variables.tfvars", "w") as tfvars_file:
            for key, value in terraform_variables.items():
                if key in ["private_subnets", "public_subnets"]:
                    value_list = value.split(",")
                    tfvars_file.write(f'{key} = {json.dumps(value_list)}\n')
                elif value.lower() in ["true", "false"]:
                    tfvars_file.write(f'{key} = {value.lower()}\n')
                else:
                    tfvars_file.write(f'{key} = "{value}"\n')

            tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')
            tfvars_file.write(f'eks_managed_node_groups = {json.dumps(eks_managed_node_groups)}\n')

    @staticmethod
    def check_aws_credentials():
        aws = AWSCredentialCheck()

        with MultiThreading() as mt:
            print('\n#### checking aws credentials ####\n')
            if mt.run_with_progress_indicator(aws.check_aws_profile, 1):
                print('aws credentials exist under ~/.aws/credentials file\n')
                return True
            else:
                print('aws credentials do not exist under ~/.aws/credentials file\n')

                if not aws.accept_aws_values():
                    return False

    def terraform_get(self, path):
        with MultiThreading() as mt:
            print('#### executing "terraform get" ####\n')
            if mt.run_with_progress_indicator(self.tf.run_terraform_command, 1, 'get', path):
                print('#### "terraform get" complete ####\n')
                return True
            else:
                print('#### "terraform get" failed ####\n')
                return False

    def terraform_init(self, path):
        with MultiThreading() as mt:
            print('#### executing "terraform init" ####\n')
            if mt.run_with_progress_indicator(self.tf.run_terraform_command, 1, 'init', path):
                print('#### "terraform init" complete ####\n')
                return True
            else:
                print('#### "terraform init" failed ####\n')
                return False

    def terraform_plan(self, path):
        with MultiThreading() as mt:
            print('#### executing "terraform plan" ####\n')
            if mt.run_with_progress_indicator(self.tf.run_terraform_command, 1, 'plan', path):
                print('#### "terraform plan" complete ####\n')
                return True
            else:
                print('#### "terraform plan" failed ####\n')
                return False

    def terraform_apply(self, path):
        with MultiThreading() as mt:
            print('#### executing "terraform apply" ####\n')
            if mt.run_with_progress_indicator(self.tf.run_terraform_command, 1, 'apply', path):
                print('#### "terraform apply" complete ####\n')
                return True
            else:
                print('#### "terraform apply" failed ####\n')
                return False

    def terraform_destroy(self, path):
        with MultiThreading() as mt:
            print('#### executing "terraform destroy" ####\n')
            if mt.run_with_progress_indicator(self.tf.run_terraform_command, 1, 'destroy', path):
                print('#### "terraform destroy" complete ####\n')
                return True
            else:
                print('#### "terraform destroy" failed ####\n')
                return False

    def create_eks_managed_node_cluster(self, config_file):
        terraform_variables, application_variables = self.read_config_file(config_file)

        config = configparser.ConfigParser()
        config.read(config_file)

        common_tags = {key: config.get("terraform_variables:common_tags", key) for key in
                       config.options("terraform_variables:common_tags")}

        eks_managed_node_groups = {
            key.split(":")[-1]: {
                subkey: [config.get(key, subkey)] if subkey == "instance_types" else config.get(key, subkey)
                for subkey in config.options(key)
            }
            for key in config.sections()
            if key.startswith("terraform_variables:group")
        }

        self.write_variables_to_tfvars(terraform_variables, common_tags, eks_managed_node_groups)
        
        if (self.check_aws_credentials() and
                self.terraform_get('./aws/eks/eks_managed_node/') and
                self.terraform_init('./aws/eks/eks_managed_node/') and
                self.terraform_plan('./aws/eks/eks_managed_node/') and
                self.terraform_apply('./aws/eks/eks_managed_node/')
        ):
            return True
        else:
            return False

    def delete_eks_managed_node_cluster(self):
        if self.terraform_destroy('./aws/eks/eks_managed_node/'):
            return True
        else:
            return False
