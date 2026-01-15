from app.services.database import db_service

# Add a known bad URL for testing (with trailing slash as URLs are normalized)
print("Adding bad.com to database...")
db_service.add_url("http://bad.com/", source="Test Feed", score=100)
print("Done.")
