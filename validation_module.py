from pydantic import BaseModel,Field, field_validator, ValidationError
from typing import Tuple, Dict

class SendOTPRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value: int) -> int:
        """Validates that the mobile number is exactly 10 digits long and contains only digits."""
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value
    
class SendLogoutRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value: int) -> int:
        """Validates that the mobile number is exactly 10 digits long and contains only digits."""
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value


class VerifyOTPRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")
    otp: int = Field(..., description="4-digit OTP")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value: int) -> int:
        """Validates that the mobile number is exactly 10 digits long and contains only digits."""
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value

    @field_validator('otp')
    def validate_otp(cls, value: int) -> int:
        """Validates that the OTP is exactly 4 digits long and contains only digits."""
        str_value = str(value)
        if len(str_value) != 4:
            raise ValueError("OTP must be exactly 4 digits long.")
        if not str_value.isdigit():
            raise ValueError("OTP must contain only digits.")
        return value
    

def handle_validation_error(error: ValidationError) -> Tuple[Dict[str, str], int]:
    """
    Maps Pydantic validation errors to appropriate status codes and error messages.

    Args:
        error (ValidationError): The validation error raised by Pydantic.

    Returns:
        Tuple[Dict[str, str], int]: A tuple containing a response dictionary and the corresponding status code.
    """
    errors = error.errors()
    response = {"message": "Validation failed", "errors": []}

    status_code = 400  

    for err in errors:
        loc = " -> ".join(err['loc'])
        error_message = f"{loc}: {err['msg']}"
        response["errors"].append(error_message)

        
        if "mobile_number" in err['loc']:
            status_code = 422  
        elif "otp" in err['loc']:
            status_code = 423 

    return response, status_code
