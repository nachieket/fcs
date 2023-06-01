import time

from functools import wraps
from modules.logging.logging import CustomLogger


class CustomDecorator:
    # def __init__(self, info_log_filename, error_log_filename):
    #     self.info_logger = CustomLogger("info_logger", info_log_filename).get_logger()
    #     self.error_logger = CustomLogger("error_logger", error_log_filename).get_logger()
    def __init__(self, info_logger, error_logger):
        self.info_logger = info_logger
        self.error_logger = error_logger

    def process_func_logger(self, original_func):
        @wraps(original_func)
        def wrapper(*args, **kwargs):
            self.info_logger.info(f'executing {original_func.__name__} with arguments => {args}')
            process = original_func(*args, **kwargs)
            self.info_logger.info(f'execution of {original_func.__name__} with arguments => {args} finished')

            if not process:
                return False
            elif process.returncode == 0 and process.stdout and process.stderr:
                self.info_logger.info(f'output start => {args}')
                self.info_logger.info(process.stdout)
                self.info_logger.info(f'output end => {args}')

                self.error_logger.error(f'error start => {args}')
                self.error_logger.error(process.stderr)
                self.error_logger.error(f'error end => {args}')

                return True
            elif process.returncode == 0 and process.stdout and not process.stderr:
                self.info_logger.info(f'output start => {args}')
                self.info_logger.info(process.stdout)
                self.info_logger.info(f'output end => {args}')

                return True
            elif process.returncode == 0 and process.stderr and not process.stdout:
                self.error_logger.error(f'error start => {args}')
                self.error_logger.error(process.stderr)
                self.error_logger.error(f'error end => {args}')

                return True
            elif process.returncode == 0:
                return True
            else:
                return False

        return wrapper

    def process_func_timer(self, original_func):

        @wraps(original_func)
        def wrapper(*args, **kwargs):

            t1 = time.time()
            process = original_func(*args, **kwargs)
            t2 = time.time() - t1

            self.info_logger.info(f'{original_func.__name__} ran in {t2} sec')

            return process

        return wrapper

    def standard_func_logger(self, original_func):
        @wraps(original_func)
        def wrapper(*args, **kwargs):
            self.info_logger.info(f'executing {original_func.__name__} with arguments => {args}')
            result = original_func(*args, **kwargs)
            self.info_logger.info(f'execution of {original_func.__name__} with arguments => {args} finished')
            return result

        return wrapper

    def standard_func_timer(self, original_func):
        @wraps(original_func)
        def wrapper(*args, **kwargs):
            t1 = time.time()
            result = original_func(*args, **kwargs)
            t2 = time.time() - t1
            self.info_logger.info(f'{original_func.__name__} ran in {t2} sec')
            return result

        return wrapper
