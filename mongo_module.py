from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

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

class MongoDBClient:
    def __init__(self, db_name):
        """Initializes the MongoDBClient with the specified database name."""
        load_dotenv()
        uri = os.getenv("MONGO_URI")
        self.client = MongoClient(uri, server_api=ServerApi('1'))
        self.db = self.client[db_name]

    def get_collection(self, collection_name):
        """Retrieves a collection from the database."""
        return self.db[collection_name]

    def insert_or_update_otp(self, collection_name, mobile: int, otp: int):
        """Inserts a new OTP or updates an existing one."""
        collection = self.get_collection(collection_name)
        current_time = datetime.now()
        expiry_time = current_time + timedelta(minutes=5)

        existing_document = collection.find_one({"phone": mobile})

        if existing_document:
            request_times = existing_document.get("request_times", [])
            request_times = [t for t in request_times if t > current_time - timedelta(minutes=30)]

            if len(request_times) >= 3:
                raise RequestLimitExceeded("Request limit reached. Please try again after 30 mins.")

            request_times.append(current_time)
            collection.update_one(
                {"phone": mobile},
                {"$set": {
                    "otp": otp, 
                    "expiry_time": expiry_time, 
                    "request_times": request_times,
                    "attempts": 0
                }}
            )
        else:
            document = {
                "phone": mobile,
                "otp": otp,
                "expiry_time": expiry_time,
                "created_at": current_time,
                "request_times": [current_time],
                "attempts": 0  
            }
            collection.insert_one(document)

    def verify_otp(self, collection_name, mobile: int, otp: int):
        """Verifies the OTP for a given mobile number."""
        collection = self.get_collection(collection_name)
        document = collection.find_one({"phone": mobile})

        if not document:
            raise NoRecord("No record found for the given phone number.")

        current_time = datetime.now()
        expiry_time = document['expiry_time']
        otp_value = document['otp']
        attempts = document.get("attempts", 0)

        if attempts >= 3:
            raise MaxAttemptsExceeded("Maximum OTP attempts exceeded. Please request a new OTP.")

        if current_time > expiry_time:
            raise Expired("OTP has expired.")

        if otp_value == otp:
            collection.update_one({"phone": mobile}, {"$set": {"attempts": 0}})
            return "OTP is valid."
        else:
            collection.update_one(
                {"phone": mobile},
                {"$inc": {"attempts": 1}}
            )
            remaining_attempts = 2 - attempts
            raise Invalid(f"Invalid OTP. Attempts remaining: {remaining_attempts}")
