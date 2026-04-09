import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "nerdy.db"))

def get_db():
    return sqlite3.connect(DB_PATH)