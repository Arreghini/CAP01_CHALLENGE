from fastapi import FastAPI, HTTPException, Depends, status
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta, timezone
from fastapi.responses import JSONResponse
from functools import reduce
from fastapi.security import OAuth2PasswordBearer

# Aplicación
app = FastAPI()


#  definición de variables y configuraciones
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

fake_db = {"users": {}}

#  Función para autenticación y validación de acceso por token. Aquí se utiliza el diccionario con los datos del usuario
#  para generar el token. Luego de define el tiempo de expiración del token como los minutos definidos de expiración, sumándolos a
#  la hora actual. Luego crea un token a partir de jwt.encode a partir de la clave secreta y algorítmo definidos 

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire.timestamp()})  # Convertir datetime a timestamp
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#  Función para validar el token. Se obtiene el token y se verifica si es válido. Si es válido, se obtiene el usuario
# Primero se compara la contraseña enviada (plain_password) con la hasheada

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password, pwd_context=pwd_context):
    return pwd_context.verify(plain_password, hashed_password)

#  Función para obtener la contraseña hash. Se obtiene la contraseña y se genera la hash
def get_password_hash(password):
    return pwd_context.hash(password)

class Payload(BaseModel):
    numbers: List[int]

class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
     access_token: str
     token_type: str                

class BinarySearchPayload(Payload):
    target: int

# Endpoint para registro de nuevos usuarios. Si todo bien se guarda la contraseña hasheada y el token de acceso
@app.post("/register", response_model=Token)
def register(user: User):
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="Username already registered")
    fake_db["users"][user.username] = {
        "username": user.username,
        "password": get_password_hash(user.password),
        "token": create_access_token(data={"sub": user.username}),
    }
    return {"access_token": fake_db["users"][user.username]["token"], "token_type": "bearer"}

# Endpoint para login. Se obtiene el usuario y se verifica si existe. Si existe, se verifica la contraseña. Si es correcta, se devuelve el token de acceso
@app.post("/login", response_model=Token)
def login(user: User):
    if user.username not in fake_db["users"]:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    if not verify_password(user.password, fake_db["users"][user.username]["password"], pwd_context):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/bubble-sort")
def bubble_sort(payload: Payload, token: str = Depends(oauth2_scheme)):
    # decodifico el token
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = decoded_token.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Lógica de ordenamiento
    numbers = payload.numbers
    n = len(numbers)
    for i in range(n):
        for j in range(0, n-i-1):
            if numbers[j] > numbers[j+1]:
                numbers[j], numbers[j+1] = numbers[j+1], numbers[j]
    
    return {"numbers": numbers}
  
@app.post("/binary-search")
def binary_search(payload: BinarySearchPayload, token: str = Depends(oauth2_scheme)):
    # Ordena la lista de números
    numbers = sorted(payload.numbers)
    target = payload.target
    low = 0
    high = len(numbers) - 1
    
    # Búsqueda binaria
    while low <= high:
        mid = (low + high) // 2
        if numbers[mid] == target:
            # Retorna el índice original del objetivo en la lista desordenada
            original_index = payload.numbers.index(target)
            return {"index": original_index}
        elif numbers[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    
    return {"index": -1}  # Retorna -1 si no se encuentra el objetivo



@app.post("/filter-even")
def filter_even(payload: Payload, token: str = Depends(oauth2_scheme)):
    return {"numbers": [number for number in payload.numbers if number % 2 == 0]}

@app.post("/sum-elements")
def sum_elements(payload: Payload, token: str = Depends(oauth2_scheme)):
    return {"sum": sum(payload.numbers)}

@app.post("/mean-value")
def mean_value(payload: Payload, token: str = Depends(oauth2_scheme)):
    return {"mean": sum(payload.numbers) / len(payload.numbers)}
@app.post("/median-elements")
def median_elements(payload: Payload, token: str = Depends(oauth2_scheme)):
    numbers = sorted(payload.numbers)
    if len(numbers) % 2 == 0:
        median = (numbers[len(numbers) // 2 - 1] + numbers[len(numbers) // 2]) / 2
    else:
        median = numbers[len(numbers) // 2]
    return {"median": median}

@app.post("/max-value")
def max_value(payload: Payload, token: str = Depends(oauth2_scheme)):
    return {"max_value": max(payload.numbers)}

@app.get("/")
def read_root():
    return {"message": "Welcome to the API"}
