from pydantic import BaseModel, Field, ValidationError, field_validator
from typing import Optional, Tuple, Dict

class InsertUserRequest(BaseModel):
    firstName: str = Field(..., description="First name of the user")
    lastName: str = Field(..., description="Last name of the user")
    district: str = Field(..., description="District of the user")
    country: str = Field(..., description="Country of the user")
    state: str = Field(..., description="State of the user")
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value: int) -> int:
        """Validates mobile number is exactly 10 digits."""
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value

class UpdateUserRequest(BaseModel):
    firstName: Optional[str] = Field(None, description="First name of the user")
    lastName: Optional[str] = Field(None, description="Last name of the user")
    district: Optional[str] = Field(None, description="District of the user")
    country: Optional[str] = Field(None, description="Country of the user")
    state: Optional[str] = Field(None, description="State of the user")
    mobile_number: Optional[int] = Field(None, description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number', mode='before')
    def validate_mobile_number(cls, value: Optional[int]) -> Optional[int]:
        """Validates mobile number if provided."""
        if value is None:
            return value
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value

class DeleteUserRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value: int) -> int:
        """Validates mobile number is exactly 10 digits."""
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value

class QueryUserRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value: int) -> int:
        """Validates mobile number is exactly 10 digits."""
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError("Mobile number must be exactly 10 digits long.")
        if not str_value.isdigit():
            raise ValueError("Mobile number must contain only digits.")
        return value

def handle_validation_error(error: ValidationError) -> Tuple[Dict[str, str], int]:
    """
    Maps Pydantic validation errors to appropriate status codes and error messages.
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

    return response, status_code
