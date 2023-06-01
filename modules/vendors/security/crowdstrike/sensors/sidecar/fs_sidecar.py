import requests
import base64
import json
import subprocess

from requests.auth import HTTPBasicAuth
from modules.logging.logging import CustomLogger
from modules.decorators.decorators import CustomDecorator


class FalconSensorSidecar:
    info_logger = CustomLogger("info_logger", '/tmp/crowdstrike/system_logs/info.log').get_logger()
    error_logger = CustomLogger("error_logger", '/tmp/crowdstrike/system_logs/error.log').get_logger()

    decorator = CustomDecorator(info_logger, error_logger)

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def __init__(self, falcon_client_id, falcon_client_secret, falcon_cid, falcon_cloud_region, falcon_cloud_api):
        self.falcon_client_id = falcon_client_id
        self.falcon_client_secret = falcon_client_secret
        self.falcon_cid = falcon_cid
        self.falcon_cloud_region = falcon_cloud_region
        self.falcon_cloud_api = falcon_cloud_api

    @decorator.standard_func_logger
    @decorator.standard_func_timer
    def deploy_falcon_sensor_sidecar(self):
        try:
            # Get Falcon API Bearer Token
            token_url = f"https://{self.falcon_cloud_api}/oauth2/token"
            token_data = {
                "client_id": self.falcon_client_id,
                "client_secret": self.falcon_client_secret,
            }
            response = requests.post(token_url, data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            falcon_api_bearer_token = response.json()['access_token']

            # Get Falcon Art Password
            url = f"https://{self.falcon_cloud_api}/container-security/entities/image-registry-credentials/v1"
            headers = {"authorization": f"Bearer {falcon_api_bearer_token}"}
            response = requests.get(url, headers=headers)
            falcon_art_password = response.json()['resources'][0]['token']

            # Get Falcon Art Username
            falcon_art_username = f"fc-{self.falcon_cid.lower().split('-')[0]}"
            sensor_type = "falcon-container"

            # Get Registry Bearer Token
            registry_bearer_url = f"https://registry.crowdstrike.com/v2/token?={falcon_art_username}&scope=repository:" \
                                  f"{sensor_type}/{self.falcon_cloud_region}/release/falcon-sensor:pull&service=registry." \
                                  f"crowdstrike.com"
            response = requests.get(registry_bearer_url, auth=HTTPBasicAuth(falcon_art_username, falcon_art_password))
            registry_bearer = response.json()['token']

            # Get Latest Sensor
            latest_sensor_url = f"https://registry.crowdstrike.com/v2/{sensor_type}/{self.falcon_cloud_region}" \
                                f"/release/falcon-sensor/tags/list"
            headers = {"authorization": f"Bearer {registry_bearer}"}
            response = requests.get(latest_sensor_url, headers=headers)
            latest_sensor = response.json()['tags'][-2]

            falcon_image_repo = f"registry.crowdstrike.com/{sensor_type}/{self.falcon_cloud_region}/release/falcon-sensor"
            falcon_image_tag = latest_sensor
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while making an HTTP request: {e}")
            self.error_logger.error(f"An error occurred while making an HTTP request: {e}")
            return False
        except KeyError as e:
            print(f"Missing key in the JSON response: {e}")
            self.error_logger.error(f"Missing key in the JSON response: {e}")
            return False
        except (IndexError, Exception) as e:
            print(f"An error occurred while accessing elements in a list: {e}")
            self.error_logger.error(f"An error occurred while accessing elements in a list: {e}")
            return False

        try:
            # Add Helm Repo
            subprocess.run(["helm", "repo", "add", "crowdstrike", "https://crowdstrike.github.io/falcon-helm"])

            # Generate Falcon Image Pull Token
            partial_pull_token = base64.b64encode(f"{falcon_art_username}:{falcon_art_password}".encode()).decode()
            falcon_image_pull_data = {
                "auths": {
                    "registry.crowdstrike.com": {
                        "auth": partial_pull_token
                    }
                }
            }

            falcon_image_pull_token = base64.b64encode(json.dumps(falcon_image_pull_data).encode()).decode()
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while running the subprocess: {e}")
            self.error_logger.error(f"An error occurred while running the subprocess: {e}")
            return False
        except TypeError as e:
            print(f"An error occurred with data types during encoding/decoding: {e}")
            self.error_logger.error(f"An error occurred with data types during encoding/decoding: {e}")
            return False
        except (json.JSONDecodeError, Exception) as e:
            print(f"An error occurred while encoding JSON data: {e}")
            self.error_logger.error(f"An error occurred while encoding JSON data: {e}")
            return False

        try:
            # Run Helm Upgrade Install
            helm_cmd = [
                "helm", "upgrade", "--install", "falcon-container", "crowdstrike/falcon-sensor",
                "-n", "falcon-system", "--create-namespace",
                "--set", "node.enabled=false",
                "--set", "container.enabled=true",
                "--set", f"falcon.cid={self.falcon_cid}",
                "--set", f"container.image.repository={falcon_image_repo}",
                "--set", f"container.image.tag={falcon_image_tag}",
                "--set", "container.image.pullSecrets.enable=true",
                "--set", "container.image.pullSecrets.namespaces=applications\\,falcon-kubernetes-protection",
                "--set", f"container.image.pullSecrets.registryConfigJSON={falcon_image_pull_token}",
            ]

            helm_process = subprocess.run(helm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if helm_process.stdout:
                self.info_logger.info(helm_process.stdout)
            if helm_process.stderr:
                self.error_logger.error(helm_process.stderr)

            return True
        except (subprocess.CalledProcessError, Exception) as e:
            print(f"An error occurred while running the subprocess: {e}")
            self.error_logger.error(f"An error occurred while running the subprocess: {e}")
            return False
