from environment_scripts.env_setup.setup_script import EnvironmentSetup
from environment_scripts.env_setup.utility import ProcessRunner


def main():
    EnvironmentSetup().execute()

if __name__ == "__main__":

    # process = ProcessRunner()
    # process.execute(command,None)

    main()
