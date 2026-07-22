class EnrollRequest(BaseModel):
    image: str = Field(max_length=15_000_000)
