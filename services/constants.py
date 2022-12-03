import os
from pathlib import Path

from dotenv import load_dotenv

dotenv_path = Path(__file__).parent.parent.absolute()
load_dotenv(dotenv_path=os.path.join(dotenv_path, '.env.dev'))
DB_USERNAME = os.getenv('PSQL_USERNAME')
DB_USER_PASSWORD = os.getenv('PSQL_USER_PASSWORD')
DB_NAME = os.getenv('PSQL_DB_NAME')

