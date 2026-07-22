class EnrollRequest(BaseModel):
    image: Annotated[str, Field(max_length=15_000_000)]
