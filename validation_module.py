from pydantic import BaseModel, Field, field_validator, ValidationError

class SendOTPRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")

    class Config:
        extra = "forbid"  

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value):
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError('Mobile number must be exactly 10 digits long.')
        if not str_value.isdigit():
            raise ValueError('Mobile number must contain only digits.')
        return value


class VerifyOTPRequest(BaseModel):
    mobile_number: int = Field(..., description="Mobile number of the user (10 digits)")
    otp: int = Field(..., description="4-digit OTP")

    class Config:
        extra = "forbid"  

    @field_validator('mobile_number')
    def validate_mobile_number(cls, value):
        str_value = str(value)
        if len(str_value) != 10:
            raise ValueError('Mobile number must be exactly 10 digits long.')
        if not str_value.isdigit():
            raise ValueError('Mobile number must contain only digits.')
        return value

    @field_validator('otp')
    def validate_otp(cls, value):
        str_value = str(value)
        if len(str_value) != 4:
            raise ValueError('OTP must be exactly 4 digits long.')
        if not str_value.isdigit():
            raise ValueError('OTP must contain only digits.')
        return value

