from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from mongo_module import MongoDBClient, MaxAttemptsExceeded, Invalid, NoRecord, RequestLimitExceeded, Expired, DuplicateUsers,UnAuthorized
from cors import add_cors_middleware
import random
from validation_module import SendOTPRequest, VerifyOTPRequest
from validation_SignupForm import InsertUserRequest

app = FastAPI()
add_cors_middleware(app)
mongo_client = MongoDBClient("OTPAuthentication")

class OTPService:
    def __init__(self, mongo_client: MongoDBClient):
        self.mongo_client = mongo_client

    def generate_otp(self) -> int:
        return random.randint(1000, 9999)

    def save_otp(self, mobile_number: int, otp: int, ip: str):
        result = self.mongo_client.insert_or_update_otp(mobile_number, otp, ip)
        if isinstance(result, str):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=result)
        return result

    def verify_otp(self, mobile_number: int, otp: int):
        result = self.mongo_client.verify_otp("users", mobile_number, otp)
        self._handle_otp_verification_exceptions(result)
        return {"message": "OTP verified successfully"}

    def _handle_otp_verification_exceptions(self, result: str):
        error_mapping = {
            "Invalid OTP.": (status.HTTP_400_BAD_REQUEST, "Invalid OTP"),
            "OTP has expired.": (status.HTTP_401_UNAUTHORIZED, "OTP expired"),
            "No record found for the given phone number.": (status.HTTP_404_NOT_FOUND, "No record found for the given phone number"),
        }
        if result.startswith("Invalid OTP. Attempts remaining"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=result)

        if result in error_mapping:
            status_code, detail = error_mapping[result]
            raise HTTPException(status_code=status_code, detail=detail)

    def register_user(self,firstName,lastName,district,country,state,mobile_number):
        """Registers a new user."""
        try:
            result = self.mongo_client.insert_users(firstName,lastName,district,country,state,mobile_number)
            return JSONResponse(status_code=status.HTTP_201_CREATED, content=result)
        except HTTPException as http_exc:
            raise http_exc 
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

def get_otp_service():
    return OTPService(mongo_client)

@app.post("/send-otp/")
async def send_otp(
    request_body: SendOTPRequest,
    request: Request,
    otp_service: OTPService = Depends(get_otp_service),
):
    ip = request.headers.get('X-Forwarded-For', request.client.host)
    if ip:
      ip = ip.split(',')[0].strip()
    otp = otp_service.generate_otp()
    otp_service.save_otp(request_body.mobile_number, otp, ip)
    return {"message": "OTP generated", "otp": otp}

@app.post("/verify-otp/")
async def verify_otp(
    request_body: VerifyOTPRequest,
    otp_service: OTPService = Depends(get_otp_service),
):
    """Verifies the OTP and raises HTTP exceptions for errors."""
    return otp_service.verify_otp(request_body.mobile_number, request_body.otp)

@app.post("/register-user/")
async def register_user(user_data: InsertUserRequest, otp_service: OTPService = Depends(get_otp_service)):
    """Registers a new user."""
    return otp_service.register_user(user_data.firstName,user_data.lastName,user_data.district,user_data.country,user_data.state,user_data.mobile_number)

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """Custom exception handler for Pydantic validation errors."""
    errors = exc.errors()
    response = {"error": "Invalid request body", "errors": []}
    status_code = status.HTTP_400_BAD_REQUEST

    for err in errors:
        loc = " -> ".join(map(str, err['loc']))
        error_message = f"{loc}: {err['msg']}"
        response["errors"].append(error_message)

    return JSONResponse(status_code=status_code, content=response)

# Custom exception handlers
@app.exception_handler(MaxAttemptsExceeded)
async def max_attempts_exception_handler(request: Request, exc: MaxAttemptsExceeded):
    return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"detail": str(exc)})

@app.exception_handler(RequestLimitExceeded)
async def request_limit_exception_handler(request: Request, exc: RequestLimitExceeded):
    return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"detail": str(exc)})

@app.exception_handler(Invalid)
async def invalid_exception_handler(request: Request, exc: Invalid):
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": str(exc)})

@app.exception_handler(NoRecord)
async def no_record_exception_handler(request: Request, exc: NoRecord):
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

@app.exception_handler(Expired)
async def expired_exception_handler(request: Request, exc: Expired):
    return JSONResponse(status_code=status.HTTP_410_GONE, content={"detail": str(exc)})

@app.exception_handler(DuplicateUsers)
async def duplicate_users_exception_handler(request: Request, exc: DuplicateUsers):
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

@app.exception_handler(UnAuthorized)
async def duplicate_users_exception_handler(request: Request, exc: UnAuthorized):
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

@app.get("/")
def greet():
    return "Welcome dear Aviral, Have fun around Development 😊😊"
