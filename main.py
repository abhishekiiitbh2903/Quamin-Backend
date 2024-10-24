from fastapi import FastAPI, Depends, HTTPException, Request, status,Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from mongo_module import MongoDBClient, MaxAttemptsExceeded, Invalid, NoRecord, RequestLimitExceeded, Expired, DuplicateUsers,UnAuthorized
from cors import add_cors_middleware
import random
from validation_module import SendOTPRequest, VerifyOTPRequest ,SendLogoutRequest
from validation_SignupForm import InsertUserRequest
from jwt import JWTManager ,JWTError


app = FastAPI()
add_cors_middleware(app)
mongo_client = MongoDBClient("OTPAuthentication")
jwt_manager=JWTManager()


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
            mongo_client=MongoDBClient("OTPAuthentication")
            user_collection=mongo_client.get_collection(mongo_client.db1,"users")
            if user_collection is not None:
                document=user_collection.find_one({"phone":mobile_number})
                verification_status = document.get("verified", False) if document else False
            if result:  
                token_data = {"mobile_number": mobile_number,"is_verified":verification_status}
                token = jwt_manager.generate_token(token_data)
                mongo_client.token_handler(token,mobile_number)
                return JSONResponse(
                    status_code=status.HTTP_201_CREATED,
                    content={"message": "User registered successfully"},
                    headers={
                        "Set-Cookie": f"quamin={token}; Path=/; HttpOnly; SameSite=Lax;" #TODO : secure to be added 
                    }
                )
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": "User registration failed"})
        except HTTPException as http_exc:
            raise http_exc 
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

def get_otp_service():
    return OTPService(mongo_client)

def get_jwt_manager():
    return JWTManager()

def get_mongo_client():
    return MongoDBClient("OTPAuthentication")

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

@app.post("/login/verify-otp/")
async def verify_otp(
    request:Request,
    response:Response,
    request_body: VerifyOTPRequest,
    otp_service: OTPService = Depends(get_otp_service),
    jwt_manager: JWTManager = Depends(get_jwt_manager),
    mongo_client: MongoDBClient = Depends(get_mongo_client)

):
    """Verifies the OTP and raises HTTP exceptions for errors."""
    result=otp_service.verify_otp(request_body.mobile_number, request_body.otp)
    if result:
        user_collection=mongo_client.get_collection(mongo_client.db1,"users")
        updated_document = user_collection.find_one({"phone": request_body.mobile_number})
        verification_status = updated_document.get("verified", False)

        # Generate a JWT token with the updated user info
        token_data = {
            "mobile_number": request_body.mobile_number,
            "is_verified": verification_status
        }
        token = jwt_manager.generate_token(token_data)

        # Store the token in the database
        mongo_client.token_handler(token, request_body.mobile_number)

        # Set the token in a secure HTTP-only cookie
        response.set_cookie(
            key="quamin",
            value=token,
            httponly=True,
            samesite="lax",  # TODO: Add 'Secure=True' when using HTTPS
            path="/"
        )
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "OTP Verified"}
        )

@app.post("/register-user/")
async def register_user(user_data: InsertUserRequest, otp_service: OTPService = Depends(get_otp_service)):
    """Registers a new user."""
    return otp_service.register_user(user_data.firstName,user_data.lastName,user_data.district,user_data.country,user_data.state,user_data.mobile_number)


@app.get("/dashboard")
def profile(request: Request):
    """
    A protected route that requires a valid JWT token to access the user's profile.
    It checks if the user is verified and ensures the token is valid and not tampered with.
    """
    try:
        token = request.cookies.get("quamin")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access denied: Token is missing. Please log in to access your profile."
            )

        jwt_manager = JWTManager()
        token_docs = mongo_client.get_collection(mongo_client.db1, "tokens")

        try:
            user_info = jwt_manager.verify_token(token)
        except JWTError as jwt_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access denied: Invalid or expired token. Please log in again."
            ) from jwt_error

        
        token_db = token_docs.find_one({"mobile_number": user_info["mobile_number"]})
        if not token_db or token_db.get("token") != token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access denied: Invalid token."
            )

        
        if not user_info.get("is_verified", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Your account is not verified. Please verify your account to access your profile."
            )

        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Access granted", "user": user_info}
        )

    except HTTPException as http_exc:
        raise http_exc  

    except Exception as e:
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}"
        )
# @app.post("/update-user")
# def update_user(

# ):
#     pass
@app.post("/logout")
def logout(
    request: Request, 
    response: Response, 
    request_body: SendLogoutRequest
):
    """
    Logs out the user by invalidating the session and setting the 'verified' status to False.
    Ensures the mobile number in the token payload matches the request body.
    """
    try:
        token = request.cookies.get("quamin")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Logout failed: No active session found (missing cookie)."
            )
        
        jwt_manager = JWTManager()
        token_docs = mongo_client.get_collection(mongo_client.db1, "tokens")

        try:
            user_info = jwt_manager.verify_token(token)
        except JWTError as jwt_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access denied: Invalid or expired token. Please log in again."
            ) from jwt_error

        
        token_db = token_docs.find_one({"mobile_number": user_info["mobile_number"]})
        if not token_db or token_db.get("token") != token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access denied: Invalid token."
            )
        
        mongo_client = MongoDBClient("OTPAuthentication")
        user_collection = mongo_client.get_collection(mongo_client.db1, "users")

        if user_collection is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error: Users collection not found."
            )

        document = user_collection.find_one({"phone": request_body.mobile_number})
        if not document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        update_result = user_collection.update_one(
            {"phone": request_body.mobile_number}, {"$set": {"verified": False}}
        )

        if update_result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Logout failed: Unable to update user status."
            )

        response.delete_cookie(key="quamin", path="/", samesite="None")

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": "Logged out successfully and user verified status set to False."}
        )

    except HTTPException as http_exc:
        raise http_exc  

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}"
        )


@app.post("/login/send-otp/")
def login(
    request: Request,
    response: Response,
    request_body: SendOTPRequest,
    otp_service: OTPService = Depends(get_otp_service),
    jwt_manager: JWTManager = Depends(get_jwt_manager),
    mongo_client: MongoDBClient = Depends(get_mongo_client)
):
    """
    Handles OTP login, sets 'verified' to True upon success, 
    and generates a JWT token with the updated user info.
    """
    try:
        # Generate OTP and send it to the user's phone
        otp = otp_service.generate_otp()
        result = mongo_client.login_send_otp(request_body.mobile_number, otp)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to send OTP. Please try again."
            )

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "OTP sent .","otp":otp}
        )

    except HTTPException as http_exc:
        raise http_exc  

    except Exception as e:
       
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}"
        )
    


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
