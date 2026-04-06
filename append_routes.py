with open("app/api/v1/endpoints/scan.py", "a") as f:
    f.write("""

@router.get("/health")
async def health():
    return {
        "status": "ok",
        "pipeline": "TGIS v2",
        "timestamp": time.time()
    }

@router.get("/history")
async def get_history(limit: int = 20, db: DatabaseService = Depends(get_db)):  
    return db.get_recent_history(limit=min(limit, 100))

@router.get("/stats")
async def get_stats(db: DatabaseService = Depends(get_db)):
    return db.get_stats()
""")
