from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
import random
from mongo_module import MongoDBClient  

app = FastAPI()

mongo_client = MongoDBClient("OTPAuthentication")

class SendOTPRequest(BaseModel):
    mobile_number: int  # Changed to int

class VerifyOTPRequest(BaseModel):
    mobile_number: int  # Changed to int
    otp: int

class OTPService:
    def __init__(self, mongo_client: MongoDBClient):
        self.mongo_client = mongo_client

    def generate_otp(self) -> int:
        """Generate a 6-digit random OTP."""
        return random.randint(100000, 999999)

    def save_otp(self, mobile_number: int, otp: int):
        """Save the generated OTP in MongoDB."""
        result = self.mongo_client.insert_or_update_otp("users", mobile_number, otp)
        return result

    def verify_otp(self, mobile_number: int, otp: int) -> str:
        """Verify the OTP against the stored OTP in MongoDB."""
        result = self.mongo_client.verify_otp("users", mobile_number, otp)
        return result

def get_otp_service():
    """Dependency function to provide an instance of OTPService."""
    return OTPService(mongo_client)

@app.get("/hello")
def greet():
    return {"hello"}

@app.post("/send-otp/")
def send_otp(request: SendOTPRequest, otp_service: OTPService = Depends(get_otp_service)):
    """Endpoint to send an OTP to the specified mobile number."""
    otp = otp_service.generate_otp()
    result = otp_service.save_otp(request.mobile_number, otp)
    if result == "Request limit reached. Please try again after 30 mins.":
        raise HTTPException(status_code=429, detail=result)
    else:
        return {"message": "OTP generated", "otp": otp}

@app.post("/verify-otp/")
def verify_otp(request: VerifyOTPRequest, otp_service: OTPService = Depends(get_otp_service)):
    """Endpoint to verify the OTP for a specified mobile number."""
    try:
        result = otp_service.verify_otp(request.mobile_number, request.otp)
        if result == "OTP is valid.":
            return {"message": "OTP verified successfully"}
        else:
            raise HTTPException(status_code=400, detail=result)  # Pass the detailed message

    except HTTPException as http_exception:
        raise http_exception
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
