with open("app/services/database.py", "r") as f:
    text = f.read()

text = text.split("db_service = PhishingDatabase()")[0] + "db_service = PhishingDatabase()\n"
text += """
DatabaseService = PhishingDatabase
def get_db():
    return db_service
"""
with open("app/services/database.py", "w") as f:
    f.write(text)
