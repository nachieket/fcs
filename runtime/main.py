import os
import subprocess

from modules.system_check.system_check import SystemCheck
from modules.custom_parser.custom_parser import CustomParser
from modules.aws_k8s_cluster_manager.aws_eks_managed_node_manager import K8sBuildEntrypoint


def add_usr_local_bin_to_path():
    # Check if /usr/local/bin is in the PATH environment variable
    path = os.environ['PATH']
    if '/usr/local/bin' not in path.split(':'):
        # Update the ~/.bashrc file with the new PATH
        with open(os.path.expanduser('~/.bashrc'), 'a') as bashrc:
            bashrc.write('\nexport PATH="/usr/local/bin:$PATH"\n')

        # Reload the ~/.bashrc file to apply the changes immediately
        subprocess.run(['bash', '-c', 'source ~/.bashrc'])


def main():
    add_usr_local_bin_to_path()

    parser = CustomParser()
    options = parser.run()

    system = SystemCheck()
    system.check_and_install_terraform()
    system.check_and_install_aws_cli()

    build = K8sBuildEntrypoint()

    if options[0] == 'aws':
        build.aws_k8s_cluster(options)
    elif options[0] == 'azure':
        pass
    elif options[0] == 'gcp':
        pass

    # parser = argparse.ArgumentParser(usage='entry.py [-h] {--create|--delete} {--eks-managed-node} [--file FILE]')
    #
    # aws_group = parser.add_argument_group('AWS')
    #
    # action_group = aws_group.add_mutually_exclusive_group(required=True)
    # action_group.add_argument('--create', action='store_true', help='Create an AWS EKS managed node cluster')
    # action_group.add_argument('--delete', action='store_true', help='Delete an AWS EKS managed node cluster')
    #
    # aws_group.add_argument('--eks-managed-node', action='store_true', help='Select an AWS EKS managed node cluster')
    # aws_group.add_argument('--file', type=str, help='Configuration file for the AWS EKS managed node cluster')
    #
    # args = parser.parse_args()
    #
    # if (args.create or args.delete) and not args.eks_managed_node:
    #     parser.error("--eks-managed-node is required with --create or --delete")
    #
    # if args.file and not args.eks_managed_node:
    #     parser.error("--file can only be used with --eks-managed-node")
    #
    # if args.file and not os.path.isfile(args.file):
    #     parser.error(f"File '{args.file}' does not exist")
    #
    # # Process the arguments and perform the desired action
    # if args.create:
    #     print("Creating an AWS EKS managed node cluster")
    #     if args.file:
    #         print(f"Using configuration file: {args.file}")
    # elif args.delete:
    #     print("Deleting an AWS EKS managed node cluster")
    #     if args.file:
    #         print(f"Using configuration file: {args.file}")
