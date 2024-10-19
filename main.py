from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import ValidationError
from mongo_module import MongoDBClient  
from cors import add_cors_middleware
import random
from validation_module import SendOTPRequest, VerifyOTPRequest 

app = FastAPI()

add_cors_middleware(app)
mongo_client = MongoDBClient("OTPAuthentication")

class OTPService:
    def __init__(self, mongo_client: MongoDBClient):
        self.mongo_client = mongo_client

    def generate_otp(self) -> int:
        return random.randint(1000, 9999)

    def save_otp(self, mobile_number: int, otp: int):
        return self.mongo_client.insert_or_update_otp("users", mobile_number, otp)

    def verify_otp(self, mobile_number: int, otp: int) -> str:
        return self.mongo_client.verify_otp("users", mobile_number, otp)

def get_otp_service():
    return OTPService(mongo_client)

@app.post("/send-otp/")
async def send_otp(request_body: SendOTPRequest, otp_service: OTPService = Depends(get_otp_service)):
    otp = otp_service.generate_otp()
    result = otp_service.save_otp(request_body.mobile_number, otp)

    if result == "Request limit reached. Please try again after 30 mins.":
        raise HTTPException(status_code=429, detail=result)

    return {"message": "OTP generated", "otp": otp}

@app.post("/verify-otp/")
async def verify_otp(request_body: VerifyOTPRequest, otp_service: OTPService = Depends(get_otp_service)):
    result = otp_service.verify_otp(request_body.mobile_number, request_body.otp)
    if result == "OTP is valid.":
        return {"message": "OTP verified successfully"}
    raise HTTPException(status_code=400, detail=result)

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return HTTPException(
        status_code=400, 
        detail={"error": "Invalid request body", "errors": exc.errors()}
    )

@app.get("/")
def greet():
    return {"hello": "world"}
