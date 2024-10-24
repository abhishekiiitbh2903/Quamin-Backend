from dotenv import load_dotenv
import os
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from mongo_module import MongoDBClient
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi


load_dotenv()
mongo_client =MongoDBClient("OTPAuthentication")


class JWTManager:
    def __init__(self):
        self.SECRET_KEY = os.getenv("SECRET_KEY")  
        uri1 = os.getenv("MONGO_URI1")
        self.client1 = MongoClient(uri1, server_api=ServerApi('1'))
        self.db1 = self.client1["OTPAuthentication"]
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY environment variable is required.")

        self.ALGORITHM = os.getenv("ALGORITHM", "HS256")  # Default to HS256
        self.ACCESS_TOKEN_EXPIRE_MINUTES = int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
        )
        
        # Optional: Use issuer and audience for more security (customize as needed)
        self.ISSUER = os.getenv("JWT_ISSUER", "your-app")
        self.AUDIENCE = os.getenv("JWT_AUDIENCE", "your-audience")

    def generate_token(self, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Generate a JWT token with optional expiration time.
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        to_encode.update({"exp": expire, "iss": self.ISSUER, "aud": self.AUDIENCE})
        return jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)

    def verify_token(self, token: str) -> Dict:
        """
        Verify the JWT token and return the payload if valid.
        Raise HTTPException if the token is invalid or expired.
        Additionally, check if the token matches the one stored in the database.
        """
        try:
            # Decode the token to extract the mobile number and verify its validity
            payload = jwt.decode(
                token,
                self.SECRET_KEY,
                algorithms=[self.ALGORITHM],
                audience=self.AUDIENCE,
                issuer=self.ISSUER,
            )
            
            # print(payload)
            # Extract the mobile number from the payload
            mobile_number = payload.get("mobile_number")
            # print(mobile_number)
            # Check if the token exists in the database

            collection = mongo_client.get_collection(self.db1, "tokens")
            print(collection)
            stored_token_entry = collection.find_one({"mobile_number": mobile_number})

            if stored_token_entry is None:
                raise HTTPException(status_code=401, detail="Token not found in database")
            # print(stored_token_entry["token"])
            # Compare the token from the database with the provided token
            if stored_token_entry["token"] != token:
                raise HTTPException(status_code=401, detail="Token does not match")
            # print(type(payload))
            return payload

        except JWTError as e:
            raise HTTPException(status_code=401, detail=f"Invalid or expired token: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")



# Reusable HTTPBearer instance to extract token from requests
auth_scheme = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> Dict:
    """
    Dependency function to protect routes. Extracts the token and verifies it.
    """
    token = credentials.credentials  
    jwt_manager = JWTManager()  
    return jwt_manager.verify_token(token)
