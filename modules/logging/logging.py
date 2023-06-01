import os
import logging

# Create /tmp/crowdstrike directory if it doesn't exist

main_log_dir = '/tmp/crowdstrike'
terraform_log_dir = os.path.join(main_log_dir, 'terraform_logs')
system_log_dir = os.path.join(main_log_dir, 'system_logs')

for log_dir in [main_log_dir, terraform_log_dir, system_log_dir]:
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)


# class CustomLogger:
#     def __init__(self, logger_name, log_file, level=logging.INFO):
#         self.logger = logging.getLogger(logger_name)
#         self.logger.setLevel(level)
#
#         formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s', datefmt='%d-%m-%Y %H:%M:%S')
#         file_handler = logging.FileHandler(log_file)
#         file_handler.setFormatter(formatter)
#
#         self.logger.addHandler(file_handler)
#
#     def get_logger(self):
#         return self.logger

class CustomLogger:
    def __init__(self, logger_name, log_file, level=logging.INFO):
        self.logger = logging.getLogger(logger_name)

        # Check if handlers are already added
        if not self.logger.handlers:
            self.logger.setLevel(level)

            formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s', datefmt='%d-%m-%Y %H:%M:%S')
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)

            self.logger.addHandler(file_handler)

    def get_logger(self):
        return self.logger

