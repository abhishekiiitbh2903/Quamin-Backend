from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from mongo_module import MongoDBClient, MaxAttemptsExceeded,Invalid,NoRecord,RequestLimitExceeded,Expired
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
        result = self.mongo_client.insert_or_update_otp("users", mobile_number, otp)
        if isinstance(result, str):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=result
            )
        return result

    def verify_otp(self, mobile_number: int, otp: int):
        """Calls MongoDB client and handles specific exceptions."""
        result = self.mongo_client.verify_otp("users", mobile_number, otp)

        if result == "Invalid OTP.":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP"
            )
        elif result == "OTP has expired.":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="OTP expired"
            )
        elif result.startswith("Invalid OTP. Attempts remaining"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=result
            )
        elif result == "No record found for the given phone number.":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No record found for the given phone number",
            )
        return {"message": "OTP verified successfully"}


def get_otp_service():
    return OTPService(mongo_client)


@app.post("/send-otp/")
async def send_otp(
    request_body: SendOTPRequest,
    otp_service: OTPService = Depends(get_otp_service),
):
    otp = otp_service.generate_otp()
    otp_service.save_otp(request_body.mobile_number, otp)
    return {"message": "OTP generated", "otp": otp}


@app.post("/verify-otp/")
async def verify_otp(
    request_body: VerifyOTPRequest,
    otp_service: OTPService = Depends(get_otp_service),
):
    """Verifies the OTP and raises HTTP exceptions for errors."""
    return otp_service.verify_otp(request_body.mobile_number, request_body.otp)


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

        if "mobile_number" in err["loc"]:
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        elif "otp" in err["loc"]:
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY

    return JSONResponse(status_code=status_code, content=response)


@app.exception_handler(MaxAttemptsExceeded)
async def max_attempts_exception_handler(request: Request, exc: MaxAttemptsExceeded):
    """Handles exceptions for exceeding max OTP verification attempts."""
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": str(exc)},
    )
@app.exception_handler(RequestLimitExceeded)
async def max_attempts_ofOTPsending_exception_handler(request: Request, exc: MaxAttemptsExceeded):
    """Handles exceptions for exceeding max OTP verification attempts."""
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": str(exc)},
    )

@app.exception_handler(Invalid)
async def invalid_exception_handler(request: Request, exc: MaxAttemptsExceeded):
    """Handles exceptions for exceeding max OTP verification attempts."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
    )

@app.exception_handler(NoRecord)
async def no_record_exception_handler(request: Request, exc: MaxAttemptsExceeded):
    """Handles exceptions for exceeding max OTP verification attempts."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )
@app.exception_handler(Expired)
async def expired_exception_handler(request: Request, exc: MaxAttemptsExceeded):
    """Handles exceptions for exceeding max OTP verification attempts."""
    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content={"detail": str(exc)},
    )


@app.get("/")
def greet():
    return {"message": "Welcome dear Aviral, Have fun around Development 😊😊"}
