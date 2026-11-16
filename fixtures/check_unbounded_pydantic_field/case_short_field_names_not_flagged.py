class CredentialsRequest(BaseModel):
    username: str
    password: str
    code: str
    redirect_uri: str
    nonce: str | None = None
    content: str | None = None
