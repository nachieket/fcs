import os
import subprocess
from modules.menu.menu import MainMenu


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

    menu = MainMenu()
    menu.main()

    print('\nrun the command "source ~/.bashrc" to update $PATH variable\n')