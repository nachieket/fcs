import subprocess
import curses
import random
import time

from modules.system_check.system_check import SystemCheck
from modules.aws.eks.eks_managed_node.eks_managed_node import EKSManagedNode


class MainMenu:
    @staticmethod
    def matrix_green_screen(stdscr):
        # Set up the curses screen
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        stdscr.nodelay(True)
        stdscr.timeout(0)
        stdscr.scrollok(True)

        # Set up the initial columns
        num_columns = curses.COLS
        columns = [1] * num_columns

        start_time = time.time()
        duration = 3  # Duration in seconds

        while time.time() - start_time < duration:
            # Randomly select a column
            col = random.randint(0, num_columns - 1)

            # Add a random character to the selected column
            char = chr(random.randint(33, 126))
            stdscr.addstr(columns[col], col, char, curses.color_pair(1))

            # Increment the column's position
            columns[col] += 1
            if columns[col] >= curses.LINES:
                columns[col] = 1

            # Sleep for a short period to control the animation speed
            time.sleep(0.00015)
            stdscr.refresh()

    @staticmethod
    def main_menu():
        print("\nPlease choose an option:\n")
        print("1. Run system checks and install required tools")
        print("2. AWS")
        print("3. Azure")
        print("4. GCP")
        print("5. Exit")

    @staticmethod
    def eks_menu():
        while True:
            print("\nPlease choose an option:\n")
            print("1. Build an EKS Managed Node Cluster using Terraform")
            print("2. Build an EKS Managed Node Cluster using Terraform + Install Daemonset Falcon Sensor")
            print("3. Generate EKS Managed Node Daemonset Helm Chart")
            print("4. Install Daemonset Falcon Sensor on Existing EKS Managed Node Cluster")
            print("5. Go Back to Previous Menu")
            print("6. Exit the Program")

            choice = input("\nEnter the number of your choice: ")

            if choice == "1":
                eks = EKSManagedNode()
                if eks.build_eks_managed_node_cluster():
                    print('aws eks managed node cluster build successful\n')
                    input('Press any key to return to menu')
                else:
                    print('aws eks managed node cluster build failed\n')
                    input('Press any key to return to menu')
            elif choice == "2":
                pass
            elif choice == "3":
                pass
            elif choice == "4":
                pass
            elif choice == "5":
                break
            elif choice == "6":
                print("\nExiting the Program.")
                exit()
            else:
                print("Invalid choice. Please try again.")

    @staticmethod
    def system():
        system = SystemCheck()
        system.check_and_install_terraform()
        system.check_and_install_aws_cli()

    def aws(self):
        while True:
            print("\nPlease choose an option:\n")
            print("1. EKS Managed Node")
            print("2. EKS Fargate")
            print("3. EKS Bottlerocket")
            print("4. Go Back to Previous Menu")
            print("5. Exit the Program")

            choice = input("\nEnter the number of your choice: ")

            if choice == "1":
                self.eks_menu()
            elif choice == "2":
                pass
            elif choice == "3":
                pass
            elif choice == "4":
                break
            elif choice == "5":
                print("\nExiting the Program.")
                exit()
            else:
                print("Invalid choice. Please try again.")

    @staticmethod
    def azure():
        print("\nYou chose option 3.")

    @staticmethod
    def gcp():
        print("\nYou chose option 4.")

    def main(self):
        while True:
            curses.wrapper(self.matrix_green_screen)
            subprocess.run('clear')
            self.main_menu()
            choice = input("\nEnter the number of your choice: ")

            if choice == "1":
                self.system()
                input('\npress any key to continue')
            elif choice == "2":
                self.aws()
            elif choice == "3":
                self.azure()
            elif choice == "4":
                self.gcp()
            elif choice == "5":
                print("\nExiting the Program.")
                break
            else:
                print("Invalid choice. Please try again.")
