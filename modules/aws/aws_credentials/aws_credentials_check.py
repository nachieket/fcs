import configparser
import os
from datetime import datetime
import subprocess


class AWSCredentialCheck:
  @staticmethod
  def find_existing_profiles(config):
    existing_profiles = []

    if config.has_section("saml"):
      existing_profiles.append("saml")

    if config.has_section("default"):
      existing_profiles.append("default")

    return existing_profiles

  @staticmethod
  def validate_profile_credentials(profile, config):
    if not config.has_section(profile):
      print(f"{profile} profile does not exist.")
      return False

    access_key_id = config.get(profile, "aws_access_key_id", fallback=None)
    secret_access_key = config.get(profile, "aws_secret_access_key", fallback=None)

    if not access_key_id or len(access_key_id) != 20:
      print(f"{profile} profile has an invalid aws_access_key_id.")
      return False

    if not secret_access_key or len(secret_access_key) != 40:
      print(f"{profile} profile has an invalid aws_secret_access_key.")
      return False

    return True

  def validate_saml_profile(self, config):
    if not self.validate_profile_credentials("saml", config):
      return False

    session_token = config.get("saml", "aws_session_token", fallback=None)
    security_token = config.get("saml", "aws_security_token", fallback=None)
    principal_arn = config.get("saml", "x_principal_arn", fallback=None)

    if not session_token or not security_token or not principal_arn:
      print("saml profile has missing values for aws_session_token, aws_security_token, or x_principal_arn.\n")
      return False

    expiry_str = config.get("saml", "x_security_token_expires", fallback=None)
    if not expiry_str:
      print("saml profile has a missing x_security_token_expires value.\n")
      return False

    expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S%z")
    now = datetime.now(expiry.tzinfo)

    if now >= expiry:
      print("\n\nsaml profile has an expired x_security_token_expires value.\n")
      return False

    return True

  def check_aws_profile(self):
    credentials_file = os.path.expanduser("~/.aws/credentials")
    if not os.path.exists(credentials_file):
      print("credentials file not found.\n")
      return False

    config = configparser.ConfigParser()
    config.read(credentials_file)

    existing_profiles = self.find_existing_profiles(config)

    if not existing_profiles:
      print("Neither saml nor default profile exists.")
      return False
    else:
      # print("Existing profiles:", ", ".join(existing_profiles))
      saml_valid = None
      default_valid = None

      if "saml" in existing_profiles:
        saml_valid = self.validate_saml_profile(config)

      if "default" in existing_profiles:
        default_valid = self.validate_profile_credentials("default", config)

      if saml_valid and not default_valid:
        print('there is no default profile but saml profile exists and is valid.')
        print('continuing the program execution with saml profile...\n')
        return True
      elif default_valid and not saml_valid:
        print('there is a default profile but no valid saml profile exists.\n')
        print('continuing the program execution with default profile...\n')
        return True
      elif default_valid and saml_valid:
        print('both default and saml profiles are valid')
        print('continuing the program execution...\n')
        return True
      else:
        return False

  @staticmethod
  def configure_aws(access_key, secret_key, region='eu-west-2', output='json'):
    try:
      aws_command = ["aws", "configure", "set"]

      subprocess.run(aws_command + ["aws_access_key_id", access_key])
      subprocess.run(aws_command + ["aws_secret_access_key", secret_key])
      subprocess.run(aws_command + ["region", region])
      subprocess.run(aws_command + ["output", output])

      print("AWS configuration complete.\n")

      return True
    except Exception as e:
      print(f"An error occurred while configuring AWS: {e}")

      return False

  def accept_aws_values(self):
    print("please provide your AWS configuration details:\n")
    aws_access_key = input("AWS Access Key ID: ")
    aws_secret_key = input("AWS Secret Access Key: ")

    default_region = input("Default region name (default - eu-west-2): ")
    if default_region == '':
      default_region = 'eu-west-2'

    default_output = input("Default output format [json, text, or yaml] (default - json): ")
    if default_output == '':
      default_output = 'json'

    if self.configure_aws(aws_access_key, aws_secret_key, default_region, default_output):
      return True
    else:
      return False

  def check_and_accept_aws_credentials(self):
    print('checking aws credentials\n')
    # self.info_logger.info('checking aws credentials')

    if self.check_aws_profile():
      print('aws credentials exist under ~/.aws/credentials file\n')
      # self.info_logger.info('aws credentials exist under ~/.aws/credentials file')
      return True
    else:
      print('aws credentials do not exist under ~/.aws/credentials file\n')
      # self.error_logger.error('aws credentials do not exist under ~/.aws/credentials file')

      if self.accept_aws_values():
        return True
      else:
        return False
