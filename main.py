from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from typing import List
from datetime import datetime
import base64

app = FastAPI(title="API de Búsqueda de Personal", version="1.0.0")

# Datos de ejemplo (mockup)
usuarios = [
    {
        "nombre": "Juan",
        "apellido1": "Castro",
        "apellido2": "Fernandez",
        "uid": "e11965920d",
        "documento": "11965920D",
        "email": "juanpablo.de.castro@uva.es",
        "colectivos": ["PDI", "Ex-Alumno", "Claustro"]
    },
    {
        "nombre": "Ana María",
        "apellido1": "Ruiz",
        "apellido2": "López",
        "uid": "e88300123x",
        "documento": "88300123X",
        "email": "ana.ruiz@uva.es",
        "colectivos": ["PAS", "Delegada"]
    },
    {
        "nombre": "Pedro",
        "apellido1": "Sánchez",
        "apellido2": "Martín",
        "uid": "e55321478k",
        "documento": "55321478K",
        "email": "pedro.sanchez@uva.es",
        "colectivos": ["PDI"]
    },
    {
        "nombre": "Laura",
        "apellido1": "Gómez",
        "apellido2": "Díaz",
        "uid": "e77440098m",
        "documento": "77440098M",
        "email": "laura.gomez@uva.es",
        "colectivos": ["Estudiante", "Ex-Alumno"]
    },
    {
        "nombre": "Daniel",
        "apellido1": "Ortega",
        "apellido2": "Ruiz",
        "uid": "e66778899h",
        "documento": "66778899H",
        "email": "daniel.ortega@uva.es",
        "colectivos": ["PAS"]
    },
    {
        "nombre": "Carmen",
        "apellido1": "Alonso",
        "apellido2": "Vega",
        "uid": "e22114455n",
        "documento": "22114455N",
        "email": "carmen.alonso@uva.es",
        "colectivos": ["PDI", "Claustro"]
    }
]

# Validaciones de autenticación
ALLOWED_IPS = {"127.0.0.1"}  # Permitir IP local en Basic Auth (ejemplo)
VALID_USER = {"username": "apiuser", "password": "secret"}  # Credenciales Basic
VALID_TOKEN = "ABC123TOKEN"  # Bearer token válido

def verificar_autenticacion(request: Request):
    # Verifica la cabecera Authorization para aceptar Basic Auth o Bearer token.
    # Aplica filtrado de IP para Basic Auth. Lanza HTTPException si falla.
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    if auth_header.startswith("Basic "):
        # Basic Auth
        try:
            basic_credentials = auth_header[len("Basic "):]
            decoded = base64.b64decode(basic_credentials).decode("utf-8")
            username, password = decoded.split(":")
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Basic Auth header")
        # Validar usuario/contraseña
        if username != VALID_USER["username"] or password != VALID_USER["password"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
        # Filtrado de IP
        client_ip = request.client.host
        if client_ip not in ALLOWED_IPS:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden from this IP")
        return True
    elif auth_header.startswith("Bearer "):
        # Bearer token
        token = auth_header[len("Bearer "):]
        if token != VALID_TOKEN:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return True
    else:
        # No coincide con Basic ni Bearer
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication scheme")

def auth_dependency(request: Request):
    verificar_autenticacion(request)
    return

def error_json(status_code: int, error: str, message: str):
    return {
        "status": status_code,
        "error": error,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }

# Funciones auxiliares
def buscar_por_uid(uid: str):
    for u in usuarios:
        if u["uid"].lower() == uid.lower():
            return u
    return None

def buscar_por_email(email: str):
    for u in usuarios:
        if u["email"].lower() == email.lower():
            return u
    return None

def filtrar_usuarios_general(query: str) -> List[dict]:
    q = query.lower()
    results = []
    for u in usuarios:
        if (q in u["uid"].lower() or
            q in u["documento"].lower() or
            q in u["nombre"].lower() or
            q in u["apellido1"].lower() or
            q in u["apellido2"].lower() or
            q in u["email"].lower()):
            results.append(u)
    return results

# Endpoints

@app.get("/personal/uid/{uid}", dependencies=[Depends(auth_dependency)])
def get_user_by_uid(uid: str):
    user = buscar_por_uid(uid)
    if user:
        return user
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_json(
        404, "Not Found", f"No existe un usuario con UID: {uid}"
    ))

@app.get("/personal/email/{email}", dependencies=[Depends(auth_dependency)])
def get_user_by_email(email: str):
    user = buscar_por_email(email)
    if user:
        return user
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_json(
        404, "Not Found", f"No existe un usuario con email: {email}"
    ))

@app.get("/personal", dependencies=[Depends(auth_dependency)])
def search_users(query: str = None):
    if not query:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_json(
            400, "Bad Request", "Debe proporcionar el parámetro 'query'."
        ))
    results = filtrar_usuarios_general(query)
    if results:
        return results
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=error_json(
        204, "No Content", f"No se encontraron usuarios para el query: '{query}'"
    ))
