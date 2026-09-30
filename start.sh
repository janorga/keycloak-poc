#!/usr/bin/env bash
# Levanta el laboratorio completo. Sin configuracion manual en la consola.
#
#   ./start.sh                             -> localhost (proyeccion en el portatil)
#   AUTHLAB_HOST=192.168.1.50 ./start.sh    -> por IP
#   AUTHLAB_HOST=mi-vm.lan ./start.sh       -> por dominio
#
# AUTHLAB_HOST es un HOST PELADO: sin esquema, sin puerto, sin ruta. El puerto lo
# pone el compose (8080 y 9090). Si no se define, vale localhost.
set -euo pipefail
cd "$(dirname "$0")"

KEYCLOAK_TIMEOUT=180
GENERATED=".generated"
# The previous-host marker lives OUTSIDE .generated/ on purpose: the generation
# step starts with `rm -rf .generated`, so a marker kept inside it would be
# destroyed before it could be read and change detection would never fire.
PREVIOUS_HOST_FILE=".authlab-host.last"

# ---------------------------------------------------------------------------
# 1. Host: validacion antes de tocar nada.
# ---------------------------------------------------------------------------
# Must be exported, not just assigned: envsubst is a child process and only
# sees variables in the environment. A plain shell assignment leaves the
# placeholder unresolved, which silently produces URLs like "http://:8080".
export AUTHLAB_HOST="${AUTHLAB_HOST:-localhost}"

die() {
  echo
  echo "ERROR: $1" >&2
  echo >&2
  exit 1
}

case "$AUTHLAB_HOST" in
  *://*|*/*)
    die "AUTHLAB_HOST debe ser un host PELADO, no una URL.
       Escribiste '$AUTHLAB_HOST'. Quita el http:// y el puerto.
       Correcto:  AUTHLAB_HOST=192.168.1.50 ./start.sh
       Correcto:  AUTHLAB_HOST=mi-vm.lan ./start.sh"
    ;;
  *:*)
    die "AUTHLAB_HOST no debe llevar puerto. El puerto lo pone el compose (8080 y 9090).
       Escribiste '$AUTHLAB_HOST'. Usa solo el host o el dominio." ;;
esac

case "$AUTHLAB_HOST" in
  ""|0.0.0.0|::|"[::]")
    die "AUTHLAB_HOST='$AUTHLAB_HOST' no sirve: es la direccion de escucha, no una
       direccion a la que un navegador pueda ir. Un alumno no puede abrir
       http://0.0.0.0:9090 en su Portable. Pon la IP o el dominio real de esta
       maquina, o deja AUTHLAB_HOST sin definir para usar localhost." ;;
esac

# Un host que no resuelve es probablemente un typo. NO es fatal: puede ser una IP,
# que por definicion no se resuelve por nombre. Solo avisa.
if ! getent hosts "$AUTHLAB_HOST" >/dev/null 2>&1; then
  echo "AVISO: '$AUTHLAB_HOST' no resuelve por DNS."
  echo "       Si es una IP es normal. Si era un dominio, revisa el typo:"
  echo "       el login fallara con 'Invalid parameter: redirect_uri'."
  echo
fi

echo "==> Host de la demo: $AUTHLAB_HOST"
if [ "$AUTHLAB_HOST" = "localhost" ]; then
  echo "    (localhost: solo desde este equipo. Para una VM o una red, define AUTHLAB_HOST)"
fi

# ---------------------------------------------------------------------------
# 2. Generar los ficheros con el host resuelto.
#
#    envsubst con '${AUTHLAB_HOST}' entrecomillado sustituye SOLO esa variable.
#    Sin las comillas, envsubst vaciaria tambien el ${client_id} de Keycloak que
#    hay en el mapper de roles del realm, y la estacion 4 (roles) fallaria en
#    silencio. No borrar las comillas.
# ---------------------------------------------------------------------------
echo "==> Resolviendo la configuracion"
rm -rf "$GENERATED"
mkdir -p "$GENERATED/realm"

envsubst '${AUTHLAB_HOST}' < config_compose.yaml.template > "$GENERATED/config.yaml"
envsubst '${AUTHLAB_HOST}' < realm/lab-realm.json.template > "$GENERATED/realm/lab-realm.json"

# Si el mapper de roles se hubiera vaciado, el realm importaria sin roles y la
# estacion 4 daria 403 a todos. Comprobacion explicita, barata y con nombre.
if grep -q '"claim.name": "resource_access\."' "$GENERATED/realm/lab-realm.json"; then
  die "El mapper de roles quedo vacio al resolver el realm (resource_access.).
       Las comillas de envsubst se han perdido. No continúes: el realm
       importaria sin roles y la estacion 4 daria 403 a todos los usuarios."
fi

# Comprobacion de que el placeholder se sustituyo de verdad y no se coló sin
# resolver en algun sitio.
if grep -q 'AUTHLAB_HOST' "$GENERATED/config.yaml" \
   || grep -q 'AUTHLAB_HOST' "$GENERATED/realm/lab-realm.json"; then
  die "Quedaron marcadores AUTHLAB_HOST sin resolver en la configuracion generada.
       Revisa las plantillas en config_compose.yaml.template y realm/."
fi

# An unresolved-but-substituted host is worse than an unresolved one: it yields
# "http://:8080" and the login fails much later with a confusing error. Catch it
# here instead.
if grep -qE 'http://:|\${AUTHLAB_HOST}' "$GENERATED/config.yaml" \
   || grep -qE 'http://:|\${AUTHLAB_HOST}' "$GENERATED/realm/lab-realm.json"; then
  die "El host salio vacio al resolver la configuracion (http://:8080).
       Suele pasar si AUTHLAB_HOST no esta exportada al entorno antes de
       llamar a envsubst. Revisa el 'export AUTHLAB_HOST=' en start.sh."
fi

# ---------------------------------------------------------------------------
# 3. Cambio de host: hay que tirar los datos de Keycloak.
#
#    `--import-realm` usa la estrategia IGNORE_EXISTING: solo importa si el
#    realm NO existe. Keycloak guarda H2 DENTRO del contenedor (este compose no
#    declara volumen), asi que mientras el contenedor viva, el realm "lab" sigue
#    ahi con las redirect URIs del host ANTERIOR. Regenerar el JSON no arregla
#    nada: Keycloak ni lo vuelve a leer. Por eso, cambiar de host exige
#    `down -v`, y por eso lo detecta este script en vez de fallar en clase.
# ---------------------------------------------------------------------------
PREVIOUS_HOST=""
[ -f "$PREVIOUS_HOST_FILE" ] && PREVIOUS_HOST="$(cat "$PREVIOUS_HOST_FILE")"

if [ -n "$PREVIOUS_HOST" ] && [ "$PREVIOUS_HOST" != "$AUTHLAB_HOST" ]; then
  echo "==> El host cambio: $PREVIOUS_HOST -> $AUTHLAB_HOST"
  echo "    Keycloak solo importa el realm si no existe, y guarda los datos dentro"
  echo "    del contenedor. Sin borrar el volumen, las redirect URIs seguirian"
  echo "    apuntando a $PREVIOUS_HOST y el login fallaria con 'Invalid parameter:"
  echo "    redirect_uri'. Reconstruyendo los datos."
  docker compose down -v 2>/dev/null || true
  rm -f "$PREVIOUS_HOST_FILE"
fi

# ---------------------------------------------------------------------------
# 4. Arranque.
# ---------------------------------------------------------------------------
echo "==> Reconstruyendo la aplicacion"
# `uv sync` descarga de PyPI, asi que el BUILD necesita internet la primera vez.
# Una vez existen las imagenes, un arranque en frio sin red no reconstruye ni
# descarga: cae a las imagenes locales. Ese fallback es lo que hace funcionar
# "reiniciar el portatil sin internet".
if ! docker compose build; then
  if docker image inspect authlab-main-app:latest >/dev/null 2>&1 \
     && docker image inspect authlab-resource-server:latest >/dev/null 2>&1; then
    echo "    El build fallo (sin red, casi seguro). Las imagenes ya estan en local:"
    echo "    se arranca con esas. Si has cambiado el codigo, conectate y ejecuta ./start.sh otra vez."
  else
    echo "    El build fallo y no hay imagenes previas. Conectate a internet y reintenta."
    exit 1
  fi
fi

echo "==> Levantando el stack"
# --force-recreate is not optional. .generated/config.yaml is bind mounted as a
# FILE, and a bind-mounted file is cached by the kernel: rewriting it on disk
# does NOT change what the running container reads. Without recreating, the app
# keeps serving the config from the previous start (with the previous host) and
# emits URLs like "http://:8080". Recreating is cheap here because the images
# are already built and nothing else is at stake.
docker compose up -d --force-recreate

echo -n "==> Esperando a que Keycloak este healthy "
start=$SECONDS
while true; do
  status=$(docker inspect --format '{{.State.Health.Status}}' authlab-keycloak 2>/dev/null || echo "missing")
  if [ "$status" = "healthy" ]; then
    echo " (listo en $((SECONDS - start))s)"
    break
  fi
  if [ $((SECONDS - start)) -gt "$KEYCLOAK_TIMEOUT" ]; then
    echo "TIMEOUT"
    echo "    Keycloak no llego a healthy en ${KEYCLOAK_TIMEOUT}s. Diagnostico:"
    docker compose logs --tail=40 keycloak
    exit 1
  fi
  echo -n "."
  sleep 3
done

# Give the two Python services a moment to bind their ports after Keycloak flips.
sleep 2

# ---------------------------------------------------------------------------
# 5. Comprobacion del issuer.
#
#    KC_HOSTNAME fija el `iss` de los tokens. Si no coincide con el host por el
#    que se entra, el login FUNCIONA y a los 60 s el refresh falla con "Invalid
#    token issuer". Es un fallo tardio y confuso (parece un bug de la app), asi
#    que se comprueba aqui, antes de que lo descubra un alumno.
# ---------------------------------------------------------------------------
ISSUER=$(curl -sf --max-time 10 "http://localhost:8080/realms/lab/.well-known/openid-configuration" 2>/dev/null \
         | grep -oE '"issuer"[[:space:]]*:[[:space:]]*"[^"]+"' \
         | head -1 | sed -E 's/.*"([^"]+)"/\1/')
EXPECTED="http://$AUTHLAB_HOST:8080/realms/lab"

if [ -n "$ISSUER" ] && [ "$ISSUER" != "$EXPECTED" ]; then
  echo
  echo "AVISO: el issuer emitido no coincide con el host configurado."
  echo "    emitido   : $ISSUER"
  echo "    esperado  : $EXPECTED"
  echo "    El login entrara pero el refresh fallara con 'Invalid token issuer'."
  echo "    Suele pasar cuando el realm ya existia con otro host: ejecuta ./reset.sh -y"
  echo
elif [ -z "$ISSUER" ]; then
  echo
  echo "AVISO: no se pudo leer el issuer. Si acabas de arrancar, Keycloak puede"
  echo "        seguir inicializando. Comprueba con: docker compose logs keycloak"
  echo
fi

# The stack is up and the issuer agrees with the requested host, so this host is
# now the one that is really running. Record it as such: the NEXT run compares
# against it to decide whether Keycloak's data has to be thrown away.
printf '%s' "$AUTHLAB_HOST" > "$PREVIOUS_HOST_FILE"

echo
cat <<BANNER

  ==============================================================
                    AuthLab listo para clase
  ==============================================================

    Host configurado    $AUTHLAB_HOST
    Access token dura   60 s (a proposito, para ver el refresh)

  --------------------------------------------------------------
    URLs
      App (estacion 0)      http://$AUTHLAB_HOST:9090
      Consola Keycloak      http://$AUTHLAB_HOST:8080/admin   (admin / admin)
      Resource server       http://resource-server:9091   (solo interno)

  --------------------------------------------------------------
    USUARIOS
      ana  / ana     roles: admin, user   -> user-only 200, admin-only 200
      luis / luis    roles: user           -> user-only 200, admin-only 403

    Cliente confidencial : web-confidential
    Cliente publico PKCE : web-public-pkce
    Secreto de demo      : demo-secret-web-confidential

  --------------------------------------------------------------
    RUTAS
      /station/flow         1. El flujo en cuatro patas
      /station/jwt          2. Anatomia del JWT y diff de claims
      /station/not-login    3. OAuth2 no es login
      /station/roles        4. AuthN != AuthZ
      /station/pkce         5. PKCE (bonus)

    El access token dura 60 s a proposito. Espera y haz clic otra vez:
    la app lo renueva sola y lo dire en pantalla.

  --------------------------------------------------------------
    Reiniciar el estado con ./reset.sh  (borra el realm y lo reimporta)

BANNER
