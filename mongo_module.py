from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta
from pymongo.errors import DuplicateKeyError
from fastapi import HTTPException, status

class RequestLimitExceeded(Exception):
    """Custom exception for OTP request limit being exceeded."""
    pass

class MaxAttemptsExceeded(Exception):
    """Custom exception for exceeding the OTP verification attempts."""
    pass

class Expired(Exception):
    """Custom exception for expired OTP."""
    pass

class Invalid(Exception):
    """Custom exception for invalid OTP."""
    pass

class NoRecord(Exception):
    """Custom exception for no record found."""
    pass

class DuplicateUsers(Exception):
    """Custom exception for duplicate users."""
    pass
class UnAuthorized(Exception):
    pass
class ipAddressLimitExceeded(Exception):
    pass
class userNotFound(Exception):
    pass
class TokenNotFound(Exception):
    pass
class TokenExpired(Exception):
    pass
class Unverified(Exception):
    pass
class Blacklisted(Exception):
    pass
class InvalidToken(Exception):
    pass

class MongoDBClient:
    def __init__(self, db_name):
        """Initializes the MongoDBClient with the specified databases."""
        load_dotenv()
        uri1 = os.getenv("MONGO_URI1")
        self.client1 = MongoClient(uri1, server_api=ServerApi('1'))
        self.db1 = self.client1[db_name]

    def get_collection(self, db, collection_name):
        """Retrieves a collection from the specified database."""
        return db[collection_name]

    def get_current_time(self):
        """Returns the current time (timezone-naive)."""
        return datetime.now()

    def is_otp_expired(self, expiry_time, current_time):
        """Checks if the OTP has expired."""
        return current_time > expiry_time
    
    def token_handler(self, token: str, mobile_number: str):
        collection = self.get_collection(self.db1, "tokens")
        result = collection.update_one(
            {"mobile_number": mobile_number}, 
            {"$set": {"token": token}},       
            upsert=True                        
        )
        if result.matched_count > 0:
            print("Token updated for mobile number:", mobile_number)
        else:
            print("New token inserted for mobile number:", mobile_number)

    def logout_handler(self, random:str):
        collection = self.get_collection(self.db1, "blacklist")
        collection.insert_one({"random": random})


    def insert_users(self, firstName, lastName, district, country, state, mobile_number):
        collection = self.get_collection(self.db1, "Users")
        collection1 = self.get_collection(self.db1, "users")
        existing_user = collection.find_one({"mobile_number": mobile_number})
        is_allowed_docs = collection1.find_one({"phone": mobile_number})

        if existing_user:
            raise DuplicateUsers(2)

        if is_allowed_docs is None or not is_allowed_docs.get("verified", False):
            raise DuplicateUsers(8)

        new_user = {
            "firstName": firstName,
            "lastName": lastName,
            "district": district,
            "state": state,
            "country": country,
            "mobile_number": mobile_number
        }

        try:
            collection.insert_one(new_user)
        except DuplicateKeyError:
            raise DuplicateUsers(2)

        return {"message": "User registered successfully."}


    def can_signup(self, mobile, ip):
        """Checks if the IP has exceeded signup attempts in the last 24 hours."""
        collection = self.get_collection(self.db1, "ip_address")
        now = self.get_current_time()
        cutoff_time = now - timedelta(hours=24)

        # Retrieve the document for the IP address
        document = collection.find_one({"_id": ip})

        if not document:
            # If no record exists for this IP, create a new one with the first attempt
            collection.insert_one({
                "_id": ip,
                "attempts": [{"mobile_number": mobile, "attempt_time": now}]
            })
            return True

        # Filter attempts within the last 24 hours
        recent_attempts = [
            attempt for attempt in document["attempts"]
            if attempt["attempt_time"] >= cutoff_time
        ]

        # Get unique mobile numbers from recent attempts
        unique_mobile_numbers = {attempt["mobile_number"] for attempt in recent_attempts}

        # Check if unique mobile numbers exceed limit
        if len(unique_mobile_numbers) > 3:
            return False

        # If there are exactly 3 unique mobile numbers, check attempts for the given mobile
        if len(unique_mobile_numbers) == 3 and mobile not in unique_mobile_numbers:
            return False  # Adding a new unique number would exceed the limit

        # Fetch recent attempts for the specific mobile number
        recent_attempts_of_mobile = [
            attempt for attempt in recent_attempts
            if attempt["mobile_number"] == mobile
        ]

        # Check if this mobile number has 3 attempts
        if len(unique_mobile_numbers) >= 3 and len(recent_attempts_of_mobile) >= 3:
            return False

        # If checks pass, log the new attempt
        collection.update_one(
            {"_id": ip},
            {"$push": {"attempts": {"mobile_number": mobile, "attempt_time": now}}}
        )
        return True

    def insert_or_update_otp(self, mobile: int, otp: int, ip):
        """Inserts or updates an OTP entry."""
        if not self.can_signup(mobile, ip):
            raise ipAddressLimitExceeded(9)

        collection1 = self.get_collection(self.db1, "users")
        collection2 = self.get_collection(self.db1, "Users")

        current_time = self.get_current_time()
        expiry_time = current_time + timedelta(minutes=5)

        existing_user = collection2.find_one({"mobile_number": mobile})
        if existing_user:
            raise DuplicateUsers(2)

        existing_document = collection1.find_one({"phone": mobile})
        request_times = []

        if existing_document:
            request_times = [
                t for t in existing_document.get("request_times", [])
                if t > current_time - timedelta(minutes=30)
            ]

            if len(request_times) >= 3:
                raise RequestLimitExceeded(3)

            request_times.append(current_time)
            collection1.update_one(
                {"phone": mobile},
                {"$set": {
                    "otp": otp,
                    "expiry_time": expiry_time,
                    "request_times": request_times,
                    "attempts": 0,
                    "verified": False
                }}
            )
        else:
            document = {
                "phone": mobile,
                "otp": otp,
                "expiry_time": expiry_time,
                "created_at": current_time,
                "request_times": [current_time],
                "attempts": 0,
                "verified": False
            }
            collection1.insert_one(document)

    def login_send_otp(self, mobile: int,otp):
            """Inserts or updates an OTP entry."""
    
            collection1 = self.get_collection(self.db1, "users")
            collection2 = self.get_collection(self.db1, "Users")

            current_time = self.get_current_time()
            expiry_time = current_time + timedelta(minutes=5)
            existing_user = collection2.find_one({"mobile_number": mobile})
            if not existing_user:
                raise userNotFound(10)

            existing_document = collection1.find_one({"phone": mobile})
            request_times = []

            if existing_document:
                request_times = [
                    t for t in existing_document.get("request_times", [])
                    if t > current_time - timedelta(minutes=30)
                ]

                if len(request_times) >= 3:
                    raise RequestLimitExceeded(3)

                request_times.append(current_time)
                update_result=collection1.update_one(
                    {"phone": mobile},
                    {"$set": {
                        "otp": otp,
                        "expiry_time": expiry_time,
                        "request_times": request_times,
                        "attempts": 0,
                        "verified": False
                    }}
                )
                if update_result.modified_count == 0:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to update OTP. Please try again."
                    )

                return {"message": "OTP sent successfully","otp":otp}

    def verify_otp(self, collection_name, mobile: int, otp: int):
        """Verifies the OTP for the given mobile number."""
        collection = self.get_collection(self.db1, collection_name)
        document = collection.find_one({"phone": mobile})

        if not document:
            raise NoRecord(4)

        current_time = self.get_current_time()
        if self.is_otp_expired(document['expiry_time'], current_time):
            raise Expired(5)

        attempts = document.get('attempts', 0)

        if attempts >= 3:
            raise MaxAttemptsExceeded(6)

        if document['otp'] == otp:
            collection.update_one(
                {"phone": mobile},
                {"$set": {"attempts": 0, "verified": True}}
            )
            return "OTP is valid and user is verified."

        collection.update_one(
            {"phone": mobile},
            {"$inc": {"attempts": 1}, "$set": {"verified": False}}
        )
        updated_attempts = attempts + 1

        if updated_attempts >= 3:
            raise MaxAttemptsExceeded(6)

        remaining_attempts = 3 - updated_attempts
        raise Invalid(7,remaining_attempts)
