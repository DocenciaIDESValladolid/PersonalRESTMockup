from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Optional
from datetime import datetime
import base64

app = FastAPI(
    title="API de Búsqueda (AND y OR en criterios parciales)",
    version="1.0.0"
)

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

# Autenticación básica de ejemplo
ALLOWED_IPS = {"127.0.0.1"}
VALID_USER = {"username": "apiuser", "password": "secret"}
VALID_TOKEN = "ABC123TOKEN"

def verificar_autenticacion(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")

    if auth_header.startswith("Basic "):
        # Basic Auth
        try:
            encoded = auth_header[len("Basic "):]
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":")
        except:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Basic Auth header")
        # Validar usuario/contraseña
        if username != VALID_USER["username"] or password != VALID_USER["password"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Basic credentials")
        # Filtrar IP
        client_ip = request.client.host
        if client_ip not in ALLOWED_IPS:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden from this IP")

    elif auth_header.startswith("Bearer "):
        # Bearer token
        token = auth_header[len("Bearer "):]
        if token != VALID_TOKEN:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    else:
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

@app.get("/personal", dependencies=[Depends(auth_dependency)])
def buscar_personas(
    nombre: Optional[str] = None,
    apellido: Optional[str] = None,
    email: Optional[str] = None,
    documento: Optional[str] = None,
    uid: Optional[str] = None,
    logic: str = "or"  # "and" o "or"
):
    """
    Búsqueda parcial en varios campos, combinable en AND u OR.
    Si logic="or", basta que coincida con alguno de los campos no nulos.
    Si logic="and", debe coincidir en todos los campos no nulos.
    """
    # Verificamos si no se han proporcionado parámetros de búsqueda
    if not (nombre or apellido or email or documento or uid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_json(
                400, 
                "Bad Request", 
                "Debe proporcionar al menos un parámetro de búsqueda"
            )
        )

    # Convertimos cada string a minúsculas para comparar
    q_nombre = nombre.lower() if nombre else None
    q_apellido = apellido.lower() if apellido else None
    q_email = email.lower() if email else None
    q_documento = documento.lower() if documento else None
    q_uid = uid.lower() if uid else None

    resultados = []

    for user in usuarios:
        # Comprobamos coincidencias parciales (substrings)
        coincide_nombre = (q_nombre in user["nombre"].lower()) if q_nombre else False
        coincide_apellido = (q_apellido in user["apellido1"].lower() or
                             q_apellido in user["apellido2"].lower()) if q_apellido else False
        coincide_email = (q_email in user["email"].lower()) if q_email else False
        coincide_documento = (q_documento in user["documento"].lower()) if q_documento else False
        coincide_uid = (q_uid in user["uid"].lower()) if q_uid else False

        if logic.lower() == "and":
            # Debe coincidir en TODOS los campos que se hayan proporcionado
            # Si el campo no se proporcionó, no es obligatorio que coincida
            # => coincide_nombre OR q_nombre is None => interpretamos que no impide la coincidencia
            # => Podemos reinterpretar en boolean logic
            # Explicación:
            # - Si q_nombre != None, coincide_nombre debe ser True.
            # - Si q_nombre == None, no afecta.
            # Repetir para los demás campos.
            must_match_all = True

            if q_nombre and not coincide_nombre:
                must_match_all = False
            if q_apellido and not coincide_apellido:
                must_match_all = False
            if q_email and not coincide_email:
                must_match_all = False
            if q_documento and not coincide_documento:
                must_match_all = False
            if q_uid and not coincide_uid:
                must_match_all = False

            if must_match_all:
                resultados.append(user)

        else:  # logic="or" por defecto
            # Basta con que alguno sea True
            if (coincide_nombre or coincide_apellido or coincide_email or 
                coincide_documento or coincide_uid):
                resultados.append(user)

    if resultados:
        return resultados
    else:
        return JSONResponse(
            status_code=status.HTTP_204_NO_CONTENT,
            content=error_json(
                204, 
                "No Content", 
                "No se encontraron usuarios que coincidan con los criterios"
            )
        )
