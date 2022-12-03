from sqlalchemy import create_engine
from constants import DB_NAME, DB_USERNAME, DB_USER_PASSWORD

engine = create_engine(f'postgresql+psycopg2://{DB_USERNAME}:'+
                       f'{DB_USER_PASSWORD}@localhost/{DB_NAME}', 
                       future=True, 
                       echo=True)
engine.connect()
