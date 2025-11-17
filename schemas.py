"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password")
    name: Optional[str] = Field(None, description="Full name")
    plan: Literal["free", "pro"] = Field("free", description="Subscription tier")
    scans_used: int = Field(0, ge=0, description="How many scans user has used in current period")
    free_scans_quota: int = Field(5, ge=0, description="Monthly free scans quota")
    profile_context: Optional[dict] = Field(default_factory=dict, description="Extra answers to personalize AI reasoning")
    is_active: bool = Field(True, description="Whether user is active")

class Session(BaseModel):
    user_id: str
    token: str

class Scan(BaseModel):
    """Records each radar scan and AI evaluation"""
    user_id: str
    input_type: Literal["image", "text"]
    text: Optional[str] = None
    image_url: Optional[str] = None
    risk_level: Literal["low", "medium", "high"]
    red_flags: List[str] = Field(default_factory=list)
    rationale: str = ""
    cost: int = 1

# Additional example retained for reference
class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    in_stock: bool = True
