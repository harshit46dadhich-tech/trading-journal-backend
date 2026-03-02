from fastapi import FastAPI, HTTPException, Header, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import bcrypt
import jwt
import os
import uuid
import io
import csv
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = MongoClient(MONGO_URL)
db = client["trading_journal"]
users_collection = db["users"]
trades_collection = db["trades"]
sessions_collection = db["user_sessions"]

# JWT secret
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")

# ============= MODELS =============

class SignupRequest(BaseModel):
    email: str
    password: str
    name: str

class LoginRequest(BaseModel):
    email: str
    password: str

class TradeRequest(BaseModel):
    date: str
    instrument: str
    strategy: str
    direction: str  # "long" or "short"
    entry_price: float
    stop_loss: float
    exit_price: float
    position_size: float
    rules_followed: bool
    emotional_trade: bool

class TradeUpdate(BaseModel):
    date: Optional[str] = None
    instrument: Optional[str] = None
    strategy: Optional[str] = None
    direction: Optional[str] = None
    entry_price: Optional[float] = None
    stop_loss: Optional[float] = None
    exit_price: Optional[float] = None
    position_size: Optional[float] = None
    rules_followed: Optional[bool] = None
    emotional_trade: Optional[bool] = None

# ============= AUTH HELPERS =============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    """Extract user_id from JWT token"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization.replace("Bearer ", "")
    user_id = verify_token(token)
    
    # Verify user exists
    user = users_collection.find_one({"user_id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user_id

# ============= TRADE CALCULATIONS =============

def calculate_r_multiple(direction: str, entry: float, stop: float, exit: float) -> float:
    """Calculate R-multiple for a trade"""
    if direction.lower() == "long":
        r = (exit - entry) / (entry - stop) if (entry - stop) != 0 else 0
    else:  # short
        r = (entry - exit) / (stop - entry) if (stop - entry) != 0 else 0
    return round(r, 2)

def calculate_pnl(direction: str, entry: float, exit: float, size: float) -> float:
    """Calculate P&L for a trade"""
    if direction.lower() == "long":
        pnl = (exit - entry) * size
    else:  # short
        pnl = (entry - exit) * size
    return round(pnl, 2)

# ============= AUTH ENDPOINTS =============

@app.post("/api/auth/signup")
async def signup(data: SignupRequest):
    """Register a new user"""
    # Check if user exists
    if users_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    hashed_pwd = hash_password(data.password)
    
    users_collection.insert_one({
        "user_id": user_id,
        "email": data.email,
        "password": hashed_pwd,
        "name": data.name,
        "auth_provider": "local",
        "created_at": datetime.now(timezone.utc)
    })
    
    # Create JWT token
    token = create_jwt_token(user_id)
    
    return {
        "token": token,
        "user": {
            "user_id": user_id,
            "email": data.email,
            "name": data.name
        }
    }

@app.post("/api/auth/login")
async def login(data: LoginRequest):
    """Login with email and password"""
    user = users_collection.find_one({"email": data.email}, {"_id": 0})
    
    if not user or not verify_password(data.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user["user_id"])
    
    return {
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "name": user["name"]
        }
    }

@app.get("/api/auth/me")
async def get_me(user_id: str = Header(None, alias="Authorization")):
    """Get current user info"""
    user_id = get_current_user(user_id)
    user = users_collection.find_one({"user_id": user_id}, {"_id": 0, "password": 0})
    return user

# ============= TRADE ENDPOINTS =============

@app.get("/api/trades")
async def get_trades(authorization: Optional[str] = Header(None)):
    """Get all trades for the current user"""
    user_id = get_current_user(authorization)
    
    trades = list(trades_collection.find({"user_id": user_id}, {"_id": 0}).sort("date", -1))
    return trades

@app.post("/api/trades")
async def create_trade(trade: TradeRequest, authorization: Optional[str] = Header(None)):
    """Create a new trade"""
    user_id = get_current_user(authorization)
    
    # Calculate R-multiple and P&L
    r_multiple = calculate_r_multiple(
        trade.direction,
        trade.entry_price,
        trade.stop_loss,
        trade.exit_price
    )
    
    pnl = calculate_pnl(
        trade.direction,
        trade.entry_price,
        trade.exit_price,
        trade.position_size
    )
    
    # Create trade document
    trade_id = f"trade_{uuid.uuid4().hex[:12]}"
    trade_doc = {
        "trade_id": trade_id,
        "user_id": user_id,
        "date": trade.date,
        "instrument": trade.instrument,
        "strategy": trade.strategy,
        "direction": trade.direction,
        "entry_price": trade.entry_price,
        "stop_loss": trade.stop_loss,
        "exit_price": trade.exit_price,
        "position_size": trade.position_size,
        "r_multiple": r_multiple,
        "pnl": pnl,
        "rules_followed": trade.rules_followed,
        "emotional_trade": trade.emotional_trade,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    trades_collection.insert_one(trade_doc)
    
    # Return without _id
    trade_doc.pop("_id", None)
    return trade_doc

@app.put("/api/trades/{trade_id}")
async def update_trade(trade_id: str, trade: TradeUpdate, authorization: Optional[str] = Header(None)):
    """Update an existing trade"""
    user_id = get_current_user(authorization)
    
    # Get existing trade
    existing = trades_collection.find_one({"trade_id": trade_id, "user_id": user_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Trade not found")
    
    # Update fields
    update_data = {}
    if trade.date is not None:
        update_data["date"] = trade.date
    if trade.instrument is not None:
        update_data["instrument"] = trade.instrument
    if trade.strategy is not None:
        update_data["strategy"] = trade.strategy
    if trade.direction is not None:
        update_data["direction"] = trade.direction
    if trade.entry_price is not None:
        update_data["entry_price"] = trade.entry_price
    if trade.stop_loss is not None:
        update_data["stop_loss"] = trade.stop_loss
    if trade.exit_price is not None:
        update_data["exit_price"] = trade.exit_price
    if trade.position_size is not None:
        update_data["position_size"] = trade.position_size
    if trade.rules_followed is not None:
        update_data["rules_followed"] = trade.rules_followed
    if trade.emotional_trade is not None:
        update_data["emotional_trade"] = trade.emotional_trade
    
    # Recalculate R and P&L if price data changed
    entry = update_data.get("entry_price", existing["entry_price"])
    stop = update_data.get("stop_loss", existing["stop_loss"])
    exit_price = update_data.get("exit_price", existing["exit_price"])
    direction = update_data.get("direction", existing["direction"])
    size = update_data.get("position_size", existing["position_size"])
    
    update_data["r_multiple"] = calculate_r_multiple(direction, entry, stop, exit_price)
    update_data["pnl"] = calculate_pnl(direction, entry, exit_price, size)
    
    trades_collection.update_one(
        {"trade_id": trade_id, "user_id": user_id},
        {"$set": update_data}
    )
    
    updated = trades_collection.find_one({"trade_id": trade_id}, {"_id": 0})
    return updated

@app.delete("/api/trades/{trade_id}")
async def delete_trade(trade_id: str, authorization: Optional[str] = Header(None)):
    """Delete a trade"""
    user_id = get_current_user(authorization)
    
    result = trades_collection.delete_one({"trade_id": trade_id, "user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Trade not found")
    
    return {"message": "Trade deleted"}

# ============= ANALYTICS ENDPOINTS =============

@app.get("/api/analytics/stats")
async def get_stats(authorization: Optional[str] = Header(None)):
    """Get dashboard statistics"""
    user_id = get_current_user(authorization)
    
    trades = list(trades_collection.find({"user_id": user_id}, {"_id": 0}))
    
    if not trades:
        return {
            "total_trades": 0,
            "win_rate": 0,
            "average_r": 0,
            "expectancy": 0,
            "profit_factor": 0,
            "current_drawdown": 0,
            "largest_losing_streak": 0,
            "total_pnl": 0,
            "total_r": 0
        }
    
    # Basic stats
    total_trades = len(trades)
    winning_trades = [t for t in trades if t["r_multiple"] > 0]
    losing_trades = [t for t in trades if t["r_multiple"] < 0]
    
    win_count = len(winning_trades)
    loss_count = len(losing_trades)
    
    win_rate = (win_count / total_trades * 100) if total_trades > 0 else 0
    
    # Average R
    total_r = sum(t["r_multiple"] for t in trades)
    average_r = total_r / total_trades if total_trades > 0 else 0
    
    # Expectancy
    avg_win_r = sum(t["r_multiple"] for t in winning_trades) / win_count if win_count > 0 else 0
    avg_loss_r = abs(sum(t["r_multiple"] for t in losing_trades)) / loss_count if loss_count > 0 else 0
    loss_rate = 1 - (win_rate / 100)
    expectancy = (win_rate / 100 * avg_win_r) - (loss_rate * avg_loss_r)
    
    # Profit Factor
    total_winning_r = sum(t["r_multiple"] for t in winning_trades)
    total_losing_r = abs(sum(t["r_multiple"] for t in losing_trades))
    profit_factor = total_winning_r / total_losing_r if total_losing_r > 0 else 0
    
    # Drawdown calculation
    sorted_trades = sorted(trades, key=lambda x: x["date"])
    cumulative_r = 0
    peak = 0
    max_drawdown = 0
    
    for trade in sorted_trades:
        cumulative_r += trade["r_multiple"]
        if cumulative_r > peak:
            peak = cumulative_r
        drawdown = peak - cumulative_r
        if drawdown > max_drawdown:
            max_drawdown = drawdown
    
    # Largest losing streak
    current_streak = 0
    max_losing_streak = 0
    
    for trade in sorted_trades:
        if trade["r_multiple"] < 0:
            current_streak += 1
            max_losing_streak = max(max_losing_streak, current_streak)
        else:
            current_streak = 0
    
    # Total P&L
    total_pnl = sum(t["pnl"] for t in trades)
    
    return {
        "total_trades": total_trades,
        "win_rate": round(win_rate, 2),
        "average_r": round(average_r, 2),
        "expectancy": round(expectancy, 2),
        "profit_factor": round(profit_factor, 2),
        "current_drawdown": round(max_drawdown, 2),
        "largest_losing_streak": max_losing_streak,
        "total_pnl": round(total_pnl, 2),
        "total_r": round(total_r, 2)
    }

@app.get("/api/analytics/equity-curve")
async def get_equity_curve(authorization: Optional[str] = Header(None)):
    """Get equity curve data (cumulative R over time)"""
    user_id = get_current_user(authorization)
    
    trades = list(trades_collection.find({"user_id": user_id}, {"_id": 0}).sort("date", 1))
    
    cumulative_r = 0
    equity_data = []
    
    for trade in trades:
        cumulative_r += trade["r_multiple"]
        equity_data.append({
            "date": trade["date"],
            "cumulative_r": round(cumulative_r, 2),
            "trade_id": trade["trade_id"]
        })
    
    return equity_data

@app.get("/api/analytics/r-histogram")
async def get_r_histogram(authorization: Optional[str] = Header(None)):
    """Get R-multiple distribution data"""
    user_id = get_current_user(authorization)
    
    trades = list(trades_collection.find({"user_id": user_id}, {"_id": 0}))
    
    # Group trades by R-multiple ranges
    histogram = {}
    for trade in trades:
        r = trade["r_multiple"]
        # Round to nearest 0.5
        bucket = round(r * 2) / 2
        histogram[bucket] = histogram.get(bucket, 0) + 1
    
    # Convert to array format
    data = [{"r_multiple": k, "count": v} for k, v in sorted(histogram.items())]
    
    return data

# ============= CSV EXPORT/IMPORT =============

@app.get("/api/trades/export")
async def export_trades(authorization: Optional[str] = Header(None)):
    """Export trades to CSV"""
    user_id = get_current_user(authorization)
    
    trades = list(trades_collection.find({"user_id": user_id}, {"_id": 0, "user_id": 0, "trade_id": 0}).sort("date", -1))
    
    if not trades:
        raise HTTPException(status_code=404, detail="No trades to export")
    
    # Create CSV in memory
    output = io.StringIO()
    fieldnames = ["date", "instrument", "strategy", "direction", "entry_price", "stop_loss", 
                  "exit_price", "position_size", "r_multiple", "pnl", "rules_followed", "emotional_trade"]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for trade in trades:
        row = {k: trade.get(k, "") for k in fieldnames}
        writer.writerow(row)
    
    output.seek(0)
    
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trades.csv"}
    )

@app.post("/api/trades/import")
async def import_trades(request: Request, authorization: Optional[str] = Header(None)):
    """Import trades from CSV"""
    user_id = get_current_user(authorization)
    
    body = await request.body()
    csv_content = body.decode('utf-8')
    
    reader = csv.DictReader(io.StringIO(csv_content))
    
    imported_count = 0
    errors = []
    
    for idx, row in enumerate(reader, start=2):  # Start at 2 (1 is header)
        try:
            # Validate required fields
            required = ["date", "instrument", "strategy", "direction", "entry_price", 
                       "stop_loss", "exit_price", "position_size"]
            
            for field in required:
                if not row.get(field):
                    raise ValueError(f"Missing required field: {field}")
            
            # Parse and calculate
            entry = float(row["entry_price"])
            stop = float(row["stop_loss"])
            exit_price = float(row["exit_price"])
            size = float(row["position_size"])
            direction = row["direction"].lower()
            
            r_multiple = calculate_r_multiple(direction, entry, stop, exit_price)
            pnl = calculate_pnl(direction, entry, exit_price, size)
            
            # Create trade
            trade_id = f"trade_{uuid.uuid4().hex[:12]}"
            trade_doc = {
                "trade_id": trade_id,
                "user_id": user_id,
                "date": row["date"],
                "instrument": row["instrument"],
                "strategy": row["strategy"],
                "direction": direction,
                "entry_price": entry,
                "stop_loss": stop,
                "exit_price": exit_price,
                "position_size": size,
                "r_multiple": r_multiple,
                "pnl": pnl,
                "rules_followed": row.get("rules_followed", "").lower() == "true",
                "emotional_trade": row.get("emotional_trade", "").lower() == "true",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            trades_collection.insert_one(trade_doc)
            imported_count += 1
            
        except Exception as e:
            errors.append(f"Row {idx}: {str(e)}")
    
    return {
        "imported": imported_count,
        "errors": errors
    }

@app.get("/api/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
