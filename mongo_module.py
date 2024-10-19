from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

class RequestLimitExceeded(Exception):
    """Custom exception for OTP request limit being exceeded."""
    pass

class MongoDBClient:
    """
    A client for interacting with a MongoDB database for OTP authentication.

    Attributes:
        db_name (str): The name of the database.
        client (MongoClient): The MongoDB client instance.
        db: The database instance.
    """

    def __init__(self, db_name):
        """
        Initializes the MongoDBClient with the specified database name.

        Args:
            db_name (str): The name of the database to connect to.
        """
        load_dotenv()
        uri = os.getenv("MONGO_URI")
        self.client = MongoClient(uri, server_api=ServerApi('1'))
        self.db = self.client[db_name]

    def get_collection(self, collection_name):
        """Retrieves a collection from the database."""
        return self.db[collection_name]

    def insert_or_update_otp(self, collection_name, mobile: int, otp: int):
        """
        Inserts a new OTP or updates an existing one for a given mobile number,
        while enforcing a limit on OTP requests.

        Args:
            collection_name (str): The name of the collection to operate on.
            mobile (int): The mobile number associated with the OTP.
            otp (int): The OTP to be stored.

        Raises:
            Exception: If an error occurs during the database operation.
        """
        try:
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
                    {"$set": {"otp": otp, "expiry_time": expiry_time, "request_times": request_times}}
                )
                print(f"Updated document for phone {mobile}.")
            else:
                created_at = current_time
                document = {
                    "phone": mobile,
                    "otp": otp,
                    "expiry_time": expiry_time,
                    "created_at": created_at,
                    "request_times": [current_time]
                }
                collection.insert_one(document)

        except RequestLimitExceeded as e:
            return str(e)
        except Exception as e:
            return f"An error occurred during OTP insertion or update: {e}"

    def verify_otp(self, collection_name, mobile: int, otp: int):
        """
        Verifies the OTP for a given mobile number.

        Args:
            collection_name (str): The name of the collection to operate on.
            mobile (int): The mobile number associated with the OTP.
            otp (int): The OTP to be verified.

        Returns:
            str: A message indicating the result of the verification.

        Raises:
            Exception: If an error occurs during the database operation.
        """
        try:
            collection = self.get_collection(collection_name)
            document = collection.find_one({"phone": mobile})

            if document:
                current_time = datetime.now()
                expiry_time = document['expiry_time']
                otp_value = document['otp']

                if current_time > expiry_time:
                    return "OTP has expired."

                if otp_value == otp:
                    return "OTP is valid."
                else:
                    return "Invalid OTP."
            else:
                return "No record found for the given phone number."

        except Exception as e:
            raise Exception(f"An error occurred during OTP verification: {e}")
