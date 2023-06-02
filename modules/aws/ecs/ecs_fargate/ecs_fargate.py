import configparser
import base64
import json
import os
import subprocess
import time

from platform import system
from collections import defaultdict

from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class CustomConfigParser(configparser.ConfigParser):
  def optionxform(self, optionstr):
    if optionstr.strip().startswith("#"):
      return None
    return super().optionxform(optionstr)


class AWSECSClusterManager:
  info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/aws/ecs/ecs_info.log').get_logger()
  error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/aws/ecs/ecs_error.log').get_logger()

  decorator = CustomDecorator(info_logger, error_logger)

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def read_config_file(self, file_path):
    if not os.path.exists(file_path):
      self.error_logger.error(f"Config file '{file_path}' not found.")
      raise FileNotFoundError(f"Config file '{file_path}' not found.")

    config = CustomConfigParser()
    config.read(file_path)

    if not config.has_section("task_definitions"):
      self.error_logger.error("No 'task_definitions' section found in config file.")
      raise ValueError("No 'task_definitions' section found in config file.")

    result = defaultdict(dict)

    for task_key in config.options("task_definitions"):
      if task_key is None:  # Ignore None keys (commented lines)
        continue

      try:
        region, env_name = task_key.split("/")
      except ValueError:
        self.error_logger.error(f"Invalid task key '{task_key}' in config file.")
        raise ValueError(f"Invalid task key '{task_key}' in config file.")

      task_defs = [
        task.strip() for task in config.get("task_definitions", task_key).split(", ")
      ]

      if env_name not in result[region]:
        result[region][env_name] = task_defs
      else:
        result[region][env_name].extend(task_defs)

    return dict(result)

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_cluster_arns(self, region, clusters):
    """Gets the ARNs of the specified clusters in the given region.

        Args:
          region: The region to get the clusters from.
          clusters: A list of cluster names, or the string `all_clusters` to get all clusters.

        Returns:
          A list of cluster ARNs.
        """

    if clusters == 'all_clusters':
      command = f"aws ecs list-clusters --region {region} --query clusterArns[] --output text"
    else:
      command = f"aws ecs describe-clusters --clusters {clusters} --region {region} " \
                f"--query clusters[0].clusterArn --output text"

    self.info_logger.info(f'executing command {command}')
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    if result.returncode != 0:
      print(f"Error executing command: {result.stderr}")
      self.error_logger.error(f"Error executing command: {result.stderr}")
    else:
      self.info_logger.info(result.stdout.rsplit())
      return result.stdout.rsplit()

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_task_definition_arns(self, region, task_definitions):
    """
    This function fetches the task definition ARNs from AWS ECS.
    :param region: The AWS region in which to list the task definitions.
    :param task_definitions: A list of task definitions to filter. If the list contains 'all_task_definitions',
                            all task definitions in the region are fetched.
    :return: A list of task definition ARNs.
    """
    task_definition_arns = []

    # Get all task definitions if 'all_task_definitions' is provided in the list
    if task_definitions[0] == 'all_task_definitions':
      command = f"aws ecs list-task-definitions --region {region} --status ACTIVE --sort DESC --query " \
                f"taskDefinitionArns[] --output text"

      self.info_logger.info(f'executing command {command}')
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

      for task_def_arn in result.stdout.rsplit():
        # Splitting the string at the last occurrence of ":"
        task_def_name, task_def_revision = task_def_arn.rsplit(":", 1)
        task_def_revision = int(task_def_revision)

        # Check if the task definition already exists in the list
        existing_task_def = [arn for arn in task_definition_arns if task_def_name in arn]

        if existing_task_def:
          # If the task definition exists but the revision is greater, update it
          existing_name, existing_revision = existing_task_def[0].rsplit(":", 1)
          if task_def_name == existing_name and task_def_revision > int(existing_revision):
            task_definition_arns.remove(existing_task_def[0])
            task_definition_arns.append(task_def_arn)
        else:
          task_definition_arns.append(task_def_arn)
    else:
      # Get specific task definitions
      for task_definition in task_definitions[0].split(','):
        command = f"aws ecs describe-task-definition --task-definition {task_definition} --region {region} " \
                  f"--output text --query taskDefinition.taskDefinitionArn"

        self.info_logger.info(f'executing command {command}')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        task_definition_arns.append(result.stdout.rsplit()[0])

    return task_definition_arns

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_cluster_specific_task_definition_arns(self, region, cluster_arns):
    task_definition_arns = []

    runtime_task_arns = self.get_runtime_task_arns(region, cluster_arns)

    for cluster, task_arns in runtime_task_arns.items():
      for arn in task_arns:
        command = f'aws ecs describe-tasks --cluster {cluster} --task {arn} --region {region} --query ' \
                  f'tasks[0].taskDefinitionArn --output text'

        self.info_logger.info(f'executing command {command}')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

        if result.returncode != 0:
          self.error_logger.error(f"Error executing command {command}")
          raise RuntimeError(f"Error executing command {command}")
        else:
          x_arn = result.stdout.rsplit()[0]
          if x_arn not in task_definition_arns:
            task_definition_arns.append(x_arn)

    return task_definition_arns

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_task_definition_json_files(self, region, task_definitions):
    task_definition_json_files = []

    for task_definition_name in task_definitions:
      command = ["aws", "ecs", "describe-task-definition", "--region", region, "--task-definition",
                 task_definition_name,
                 "--output", "json"]
      try:
        self.info_logger.info(f'executing command {command}')
        output = subprocess.check_output(command)
      except subprocess.CalledProcessError as e:
        self.error_logger.error(f"Error executing command: {e.stderr}")
        raise RuntimeError(f"Error executing command: {e.stderr}")

      try:
        data = json.loads(output)
      except json.JSONDecodeError:
        self.error_logger.error("Unable to parse JSON response from describe-task-definition command.")
        raise ValueError("Unable to parse JSON response from describe-task-definition command.")

      task_definition_data = data['taskDefinition']

      for field in ["compatibilities", "registeredAt", "registeredBy", "requiresAttributes", "revision", "status",
                    "taskDefinitionArn"]:
        task_definition_data.pop(field, None)

      name, version = task_definition_name.split('/')[-1].split(':')

      try:
        with open(f"tmp/aws/ecs/task_definitions/{region}__{name}__{version}.json", "w") as f:
          json.dump(task_definition_data, f, indent=2)
        task_definition_json_files.append(f'{region}__{name}__{version}.json')
      except IOError as e:
        self.error_logger.error(f"Error writing task definition JSON file: {e}")
        raise RuntimeError(f"Error writing task definition JSON file: {e}")

    return task_definition_json_files

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_pull_token(self, aws_keys):
    # Get the login password for ECR
    self.info_logger.info(f'executing command to get ecr login password')

    login_password = subprocess.check_output(
      ["aws", "ecr", "get-login-password", "--region", aws_keys["aws_repo_region"]]
    ).decode("utf-8").strip()

    # Create the auth string
    auth_string = f"AWS:{login_password}"

    # Encode the auth string in base64
    auth_base64 = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")

    # Create the auths JSON object
    auths = {
      "auths": {
        f"{aws_keys['aws_account_id']}.dkr.ecr.{aws_keys['aws_repo_region']}.amazonaws.com": {
          "auth": auth_base64
        }
      }
    }

    # Convert auths object to a JSON string
    auths_json = json.dumps(auths)

    # Base64 encode the auths JSON string
    if system() == "Darwin":  # Mac OS
      pull_token = base64.b64encode(auths_json.encode("utf-8")).decode("utf-8")
    elif system() == "Linux":
      pull_token = base64.b64encode(auths_json.encode("utf-8"), altchars=None).decode("utf-8").rstrip("\n")
    else:
      self.error_logger.error("This function only supports macOS and Linux.")
      raise NotImplementedError("This function only supports macOS and Linux.")

    return pull_token

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def login_to_ecr(self, aws_keys):
    try:
      ecr_login = f'sudo docker login -u AWS -p $(aws ecr get-login-password --region {aws_keys["aws_repo_region"]}) ' \
                  f'{aws_keys["aws_account_id"]}.dkr.ecr.eu-west-2.amazonaws.com/{aws_keys["aws_repo"]}'

      self.info_logger.info(f'executing command {ecr_login}')
      result = subprocess.run(ecr_login, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

      if result.returncode != 0:
        self.error_logger.error(f"Error executing command {ecr_login}: {result.stderr}")
        raise RuntimeError(f"Error executing command {ecr_login}: {result.stderr}")
      else:
        return True
    except Exception as e:
      self.error_logger.error(f"An error occurred while running the ecr_login command: {e}")
      print(f"An error occurred while running the ecr_login command: {e}")
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def patch_task_definitions(self, aws_keys, task_definition_filenames):
    patched_filenames = []
    cwd = os.getcwd()

    self.info_logger.info('trying to get pull token')
    pull_token = self.get_pull_token(aws_keys)
    self.info_logger.info('got the pull token')

    self.info_logger.info('trying to login to aws ecr')
    self.login_to_ecr(aws_keys)
    self.info_logger.info('login to aws ecr complete')

    for filename in task_definition_filenames:
      try:
        file_path = os.path.join(os.getcwd(), f'tmp/aws/ecs/task_definitions/{filename}')

        with open(file_path, "r") as f:
          content = json.loads(f.read())

          if content['containerDefinitions'][0].get('entryPoint'):
            if "/tmp/CrowdStrike/rootfs/entrypoint-ecs.sh" in content['containerDefinitions'][0]['entryPoint']:
              continue

        mv_file = f"sudo cp -f {cwd}/tmp/aws/ecs/task_definitions/{filename} " \
                  f"{cwd}/tmp/aws/ecs/temp_definition/taskdefinition.json"

        result = subprocess.run(mv_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

        if result.returncode != 0:
          raise RuntimeError(f"Error executing command: {result.stderr}")
      except Exception as e:
        print(f"An error occurred while running the 'cp -f file' command: {e}")
        continue

      try:
        docker_run = f'sudo docker run --rm -v {cwd}/tmp/aws/ecs/temp_definition:/var/run/spec --rm ' \
                     f'{aws_keys["aws_account_id"]}.dkr.ecr.{aws_keys["aws_repo_region"]}.' \
                     f'amazonaws.com/{aws_keys["aws_repo"]}:{aws_keys["image_version"]} ' \
                     f'-cid {aws_keys["falcon_cid"]} ' \
                     f'-image {aws_keys["aws_account_id"]}.dkr.ecr.{aws_keys["aws_repo_region"]}.' \
                     f'amazonaws.com/{aws_keys["aws_repo"]}:{aws_keys["image_version"]} ' \
                     f'-ecs-spec-file /var/run/spec/taskdefinition.json ' \
                     f'-pulltoken {pull_token} > tmp/aws/ecs/patched_definitions/{filename}'

        self.info_logger.info(f'executing command: {docker_run}')
        result = subprocess.run(docker_run, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

        if result.returncode != 0:
          self.error_logger.error(f"Error executing command: {result.stderr}")
          raise RuntimeError(f"Error executing command: {result.stderr}")
        else:
          self.info_logger.info(filename.split('.')[0], ' patched with falcon container')
          patched_filenames.append(filename)
      except Exception as e:
        self.error_logger.error(f"An error occurred while running the docker_run command with {filename}. Error: {e}")
        print(f"An error occurred while running the docker_run command with {filename}. Error: {e}")

    return patched_filenames

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_runtime_task_arns(self, region, clusters):
    runtime_task_arns = {}

    for cluster in clusters:
      command = f"aws ecs list-tasks --region {region} --cluster {cluster} --query taskArns[] --output text"

      self.info_logger.info(f'executing command {command}')
      result = subprocess.run(command, capture_output=True, text=True, shell=True)

      if result.returncode != 0:
        print(f"Error executing command {command}: {result.stderr}")
        self.error_logger.error(f"Error executing command {command}: {result.stderr}")
      else:
        runtime_task_arns[cluster] = {}
        runtime_task_arns[cluster] = result.stdout.rsplit()

    return runtime_task_arns

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def register_task_definitions(self, patched_filenames):
    registered_definitions = []
    cwd = os.getcwd()

    for filename in patched_filenames:
      region, definition, _ = filename.split('__')

      try:
        command = f'aws ecs register-task-definition --region {region} ' \
                  f'--cli-input-json ' \
                  f'file://{cwd}/tmp/aws/ecs/patched_definitions/{filename}'

        self.info_logger.info(f'executing command: {command}')
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
          raise RuntimeError(f"Error executing command {command}")
        else:
          command = f'aws ecs list-task-definitions --family-prefix {definition} ' \
                    f'--region {region} --sort DESC --output json'

          self.info_logger.info(f'executing command: {command}')
          result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

          data = json.loads(result.stdout)

          registered_definitions.append(data['taskDefinitionArns'][0])
      except Exception as e:
        self.error_logger.error(f"An error {e} occurred while registering a task definition: {definition}")
        print(f"An error {e} occurred while registering a task definition: {definition}")

    return registered_definitions

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_task_map(self, region, cluster, task_name):
    """
    This function returns a map of task details including task ARN, security group ID, subnet ID, cluster ARN,
    launch type, task definition ARN, containers, and tags.

    Args:
        region (str): The AWS region where the ECS cluster is located.
        cluster (str): The name or ARN of the ECS cluster.
        task_name (str): The name of the task.

    Returns:
        dict: A dictionary containing the task details, or False if an error occurs.
    """

    # Execute aws ecs describe-tasks command to get task details
    describe_task = f"aws ecs describe-tasks --cluster {cluster} --region {region} --tasks {task_name} " \
                    f"--include TAGS --output json"

    self.info_logger.info(f'executing command: {describe_task}')
    task_result = subprocess.run(describe_task, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    # Raise error if command execution failed
    if task_result.returncode != 0:
      self.error_logger.error(f"Error executing command {describe_task}. Error: {task_result.stderr}")
      print(f"Error executing command {describe_task}. Error: {task_result.stderr}")
      return False

    try:
      # Load task details from the command output
      task_data = json.loads(task_result.stdout)
      network_interface_id = task_data['tasks'][0]['attachments'][0]['details'][1]['value']

      # Execute aws ec2 describe-network-interfaces command to get security group details
      get_security_group = "aws ec2 describe-network-interfaces --network-interface-ids " \
                           f"{network_interface_id} --region {region} " \
                           f"--query 'NetworkInterfaces[0].Groups[].GroupId' --output text"

      self.info_logger.info(f'executing command: {get_security_group}')
      int_result = subprocess.run(get_security_group, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  shell=True)

      # Raise error if command execution failed
      if int_result.returncode != 0:
        self.error_logger.error(f"Error executing command {get_security_group}. Error: {int_result.stderr}")
        print(f"Error executing command {get_security_group}. Error: {int_result.stderr}")
        return False

      # Extract security group id from the command output
      security_group_id = int_result.stdout.strip()

      # Construct the task map
      task_map = {
        'taskArn': task_name,
        'securityGroupId': security_group_id,
        'subnetId': task_data['tasks'][0]['attachments'][0]['details'][0]['value'],
        'clusterArn': task_data['tasks'][0]['clusterArn'],
        'launchType': task_data['tasks'][0]['launchType'],
        'taskState': task_data['tasks'][0]['lastStatus'],
        'taskDefinitionArn': task_data['tasks'][0]['taskDefinitionArn'],
        # 'containers': task_data['tasks'][0]['containers'],
        'tags': task_data['tasks'][0]['tags']
      }

      return task_map
    except (json.JSONDecodeError, IndexError, KeyError, Exception) as e:
      self.error_logger.error(f"An error occurred while processing task details: {e}")
      # print(f"An error occurred while processing task details: {e}")
      return False

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_definitions_maps(self, region, cluster_arns, registered_definitions):
    """
    This function creates a map of ECS task definitions to their associated runtime tasks. The output dictionary
    maps from task definition ARNs to a sub-dictionary, which contains a list of tasks associated with that
    task definition and a count of these tasks. Only running tasks are included.

    Args:
        region (str): The AWS region where the tasks are running.
        cluster_arns (list): List of ARNs of ECS clusters to consider.
        registered_definitions (list): List of registered task definitions to consider.

    Returns:
        dict: A dictionary mapping from task definition ARNs to a dictionary containing
              a list of associated runtime tasks and a count of these tasks.
    """
    definition_maps = {}

    # Iterate over each cluster ARN
    for cluster_arn in cluster_arns:
      definition_maps[cluster_arn] = {}

      # Get a list of runtime task ARNs for the cluster
      runtime_task_arns = self.get_runtime_task_arns(region, [cluster_arn])

      if not runtime_task_arns:
        # If there are no runtime tasks, remove the cluster from the map and continue to the next cluster
        del definition_maps[cluster_arn]
        continue

      # Iterate over each registered definition
      for reg_def in registered_definitions:
        tasks = []
        for task_arns in runtime_task_arns.values():
          for task_arn in task_arns:
            task_map = self.get_task_map(region, cluster_arn, task_arn)

            # Only consider tasks that are currently running
            if (
              task_map and task_map.get('taskState') == 'RUNNING'
            ) and (
              reg_def.split(':')[-2] == task_map['taskDefinitionArn'].split(':')[-2]
            ):
              tasks.append(task_map)

        # Only add the task definition to the map if it has running tasks
        if tasks:
          definition_maps[cluster_arn][reg_def] = {
            'tasks': tasks,
            'count': len(tasks)
          }

    # Remove clusters without any running tasks from the definition map
    definition_maps = {cluster: defs for cluster, defs in definition_maps.items() if defs}

    return definition_maps

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def launch_tasks(self, region, task_arns, definition):
    """Launch new tasks in ECS clusters.

    Args:
        region (str): The AWS region where the tasks should be launched.
        task_arns (list): A list of task ARNs. Each ARN is represented by a dict
                          that includes 'clusterArn', 'launchType', 'subnetId'
                          and 'securityGroupId'.
        definition (str): The ECS task definition that new tasks should be launched with.

    Returns:
        dict: A dictionary where each key is a cluster ARN and its corresponding value is a list
              of task ARNs that were launched in that cluster.
    """
    launched_task_arns = {}

    for arn in task_arns:
      command = f"aws ecs run-task --cluster {arn['clusterArn']} " \
                f"--launch-type {arn['launchType']} " \
                f"--task-definition {definition} " \
                "--count 1 " \
                "--platform-version LATEST " \
                f"--network-configuration 'awsvpcConfiguration={{subnets=[{arn['subnetId']}]," \
                f"securityGroups=[{arn['securityGroupId']}],assignPublicIp=ENABLED}}' " \
                f"--region {region}"

      self.info_logger.info(f'executing command: {command}')
      result = subprocess.run(command, capture_output=True, text=True, shell=True)

      if result.returncode != 0:
        print(f"Error executing command {command}: {result.stderr}")
      else:
        data = json.loads(result.stdout)
        task_id = data['tasks'][0]['taskArn']  # Extract the task ARN from the response

        print(f"Successfully launched a task {task_id} for definition: {definition}.")

        # If the cluster ARN is not yet a key in the dictionary, initialize it with an empty list
        if arn['clusterArn'] not in launched_task_arns:
          launched_task_arns[arn['clusterArn']] = []

        # Append the task ARN to the list corresponding to the cluster ARN
        launched_task_arns[arn['clusterArn']].append(task_id)

    return launched_task_arns

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def check_task_status(self, region, launched_task_arns):
    """Check the status of launched tasks in ECS clusters.

    This function will check if the recently launched tasks are in 'RUNNING' state. It checks every 2 seconds
    for a duration of up to 120 seconds (i.e., 2 minutes).

    Args:
        region (str): The AWS region where the tasks are launched.
        launched_task_arns (dict): A dictionary with cluster ARNs as keys and task ARNs as values.

    Returns:
        bool: True if all tasks are running, False otherwise.
    """
    failed = 0

    self.info_logger.info('\nChecking if the recently launched tasks are running...\n')

    for cluster_arn, launched_task_arns in launched_task_arns.items():
      for launched_task_arn in launched_task_arns:
        counter = 0
        max_attempts = 60  # The maximum number of attempts to check the task status.

        # Poll the status of the task every 2 seconds until it is 'RUNNING' or until the max number of
        # attempts is reached.
        try:
          while counter < max_attempts:
            command = f"aws ecs describe-tasks --cluster {cluster_arn} " \
                      f"--tasks {launched_task_arn} --region {region}"

            response = subprocess.check_output(command, shell=True)
            response_json = json.loads(response)

            status = response_json['tasks'][0]['lastStatus']

            if status == 'RUNNING':
              self.info_logger.info(f"{launched_task_arn} task is now running")
              break
            elif status == 'STOPPED':
              failed += 1
              self.error_logger.error(f"{launched_task_arn} task stopped unexpectedly")
              raise Exception(f"{launched_task_arn} task stopped unexpectedly")

            time.sleep(2)
            counter += 1

          if counter == max_attempts:
            self.info_logger.info(f'{launched_task_arn} failed to run')
            self.info_logger.info('this program will not terminate old tasks')
            failed += 1
        except Exception as e:
          self.error_logger.error(f'{launched_task_arn} failed to run. Error: {e}')

    return failed == 0

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def remove_old_tasks(self, region, task_arns):
    """Stop old tasks in ECS clusters.

    This function will stop all tasks provided in the list `task_arns`.

    Args:
        region (str): The AWS region where the tasks are located.
        task_arns (list): A list of dictionaries, where each dictionary contains
                          'clusterArn' and 'taskArn' keys representing an ECS task.

    Returns:
        bool: True if all tasks are successfully stopped, False otherwise.
    """
    failed = 0

    for task_arn in task_arns:
      if not isinstance(task_arn, dict):
        continue

      try:
        command = f"aws ecs stop-task --cluster {task_arn['clusterArn']} --task {task_arn['taskArn']} --region {region}"

        self.info_logger.info(f'executing command: {command}')
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
          failed += 1
          self.error_logger.error(f"Error executing command: {result.stderr}")
        else:
          self.info_logger.info(task_arn['taskArn'], 'task stopped successfully')
      except Exception as e:
        failed += 1
        self.error_logger.error(f"{task_arn['taskArn']} did not stop successfully. Error: {e}")

    return failed == 0

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def run_and_stop_tasks(self, region, definitions_maps, stop_tasks='yes'):
    """Run new tasks and stop old tasks in ECS clusters.

    This function will launch new tasks for each task definition provided,
    check their status, and if they are running successfully, it will stop the old tasks.

    Args:
        region (str): The AWS region where the tasks are located.
        definitions_maps (dict): A dictionary mapping task definitions to tasks.
                                 Each task is represented as a dictionary mapping cluster ARNs to task ARNs.
        stop_tasks: Selecting yes will stop all the old tasks after launching new ones

    Returns:
        bool: True if all tasks are successfully launched and old tasks are removed, False otherwise.
    """
    # Initialize failure count
    failure_count = 0

    for definitions in definitions_maps.values():
      for definition, tasks in definitions.items():
        for _, task_arns in tasks.items():
          # If task_arns is not a list, continue to the next iteration
          if not isinstance(task_arns, list):
            continue

          # Launch new tasks
          launched_task_arns = self.launch_tasks(region, task_arns, definition)

          # If no tasks were launched, increment failure count
          if not launched_task_arns:
            failure_count += 1
            continue

          # Check status of launched tasks
          task_status = self.check_task_status(region, launched_task_arns)

          # If tasks failed, increment failure count
          if not task_status:
            failure_count += 1
            continue

          if stop_tasks == 'yes':
            # Stop old tasks
            removal_status = self.remove_old_tasks(region, task_arns)

            # If old tasks removal failed, increment failure count
            if not removal_status:
              failure_count += 1

    # If any operation failed, return False. Otherwise, return True
    return failure_count == 0

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def get_aws_keys(self, options):
    keys_to_extract = ['ecs_falcon_cid', 'ecs_image_uri']
    keys = {key: options[key] for key in keys_to_extract if options.get(key) is not None}

    ecs_image_uri_parts = keys['ecs_image_uri'].split('.')
    aws_account_id = ecs_image_uri_parts[0]
    aws_repo_region = ecs_image_uri_parts[3]

    ecs_image_uri_parts = keys['ecs_image_uri'].split('/')
    aws_repo = ecs_image_uri_parts[1].split(':')[0]
    image_version = ecs_image_uri_parts[1].split(':')[1]

    return {
      'aws_account_id': aws_account_id,
      'aws_repo_region': aws_repo_region,
      'aws_repo': aws_repo,
      'image_version': image_version,
      'falcon_cid': keys['ecs_falcon_cid']
    }

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def patch_definition_ops(self, region, clusters, task_definitions, aws_keys):
    # Get a list of relevant cluster arns
    self.info_logger.info('getting a list of cluster arns')
    cluster_arns = self.get_cluster_arns(region, clusters)
    self.info_logger.info(f'{cluster_arns}')

    # Get a list of relevant task definition arns
    self.info_logger.info('getting a list of task definitions')
    if clusters != 'all_clusters' and task_definitions[0] == 'all_task_definitions':
      task_definition_arns = self.get_cluster_specific_task_definition_arns(region, cluster_arns)
      self.info_logger.info(f'{task_definition_arns}')
    else:
      task_definition_arns = self.get_task_definition_arns(region, task_definitions)
      self.info_logger.info(f'{task_definition_arns}')

    # Download task definition json files to task_definitions directory
    self.info_logger.info('downloading task definition files in json format')
    task_definition_json_files = self.get_task_definition_json_files(region, task_definition_arns)
    self.info_logger.info(f'{task_definition_json_files}')

    # Patch task definitions and get a list of patched files
    # Note: This method will ignore the task definitions with a Falcon Sensor
    self.info_logger.info('patching task definition files and preparing a list of patched filenames')
    patched_filenames = self.patch_task_definitions(aws_keys, task_definition_json_files)
    self.info_logger.info(f'{patched_filenames}')

    return patched_filenames, cluster_arns

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def register_definition_ops(self, patched_filenames):
    # Register task definitions
    self.info_logger.info('registering task definitions')
    registered_definitions = self.register_task_definitions(patched_filenames)
    self.info_logger.info(f'{registered_definitions}')

    return registered_definitions

  def definition_start_stop_ops(self, region, cluster_arns, clusters, options, registered_definitions):
    # Get maps of all definitions with the details of tasks to be deployed and stopped
    self.info_logger.info('getting maps of all definitions with the details of tasks to be deployed and '
                          'stopped')
    definitions_maps = self.get_definitions_maps(region, cluster_arns, registered_definitions)
    self.info_logger.info(f'{definitions_maps}')

    # Check the final status to see if the method was able to start new tasks and stop old ones
    self.info_logger.info('checking to see if the method was able to start new tasks and then stop old tasks')

    if options['ecs_stop_previous_tasks'] == 'yes':
      status = self.run_and_stop_tasks(region, definitions_maps)
    else:
      stop_tasks = 'no'
      status = self.run_and_stop_tasks(region, definitions_maps, stop_tasks)

    self.info_logger.info(f'{status}')

    if status:
      print(f'Deployment on {clusters} within {region} successful.\n')
      self.info_logger.info(f'Deployment on {clusters} within {region} successful.\n')
    else:
      print(f'Deployment on {clusters} within {region} failed.\n')
      self.info_logger.info(f'Deployment on {clusters} within {region} failed.\n')

  @decorator.standard_func_logger
  @decorator.standard_func_timer
  def start_ecs_cluster_operations(self, options):
    if options.get('ecs_config_file') is not None:
      file_path = options.get('ecs_config_file')
    else:
      file_path = 'conf/aws/ecs/ecs-fargate.config'

    aws_keys = self.get_aws_keys(options)

    config_file_parameters = self.read_config_file(file_path)

    for region, ecs_clusters in config_file_parameters.items():
      print(f'starting requested operations on region {region}\n')
      self.info_logger.info(f'starting requested operations on region {region}\n')

      for clusters, task_definitions in ecs_clusters.items():
        patched_filenames, cluster_arns = self.patch_definition_ops(region, clusters, task_definitions, aws_keys)

        if options['ecs_register_definitions'] == 'yes':
          registered_definitions = self.register_definition_ops(patched_filenames)

          if options['ecs_launch_new_tasks'] == 'yes':
            if registered_definitions:
              self.definition_start_stop_ops(region, cluster_arns, clusters, options, registered_definitions)
