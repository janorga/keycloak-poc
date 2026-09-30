#!/usr/bin/env bash
# Devuelve el laboratorio al estado inicial.
#
# El `-v` NO es opcional. Sin el, el volumen de Keycloak sobrevive, el realm
# `lab` ya existe en la base de datos, y `--import-realm` usa la estrategia
# IGNORE_EXISTING: no reimporta nada. El script diria que ha reiniciado el
# estado cuando en realidad no ha cambiado nada.
set -euo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" != "-y" ] && [ "${1:-}" != "--yes" ]; then
  cat <<'WARN'

  Esto va a BORRAR el volumen de datos de Keycloak: todos los realms, clientes,
  usuarios y roles que se hayan creado a mano dentro del laboratorio.

  Se vuelve a importar realm/lab-realm.json al arrancar, asi que el laboratorio
  queda como nuevo. Lo que no se recupera es cualquier realm creado a mano.

  Para continuar con -y:  ./reset.sh -y

WARN
  read -r -p "¿Seguro? [s/N] " reply
  case "$reply" in
    [sSyY]*) ;;
    *) echo "Cancelado. No se ha tocado nada."; exit 0 ;;
  esac
fi

echo "==> Parando y borrando el volumen"
docker compose down -v

# Un reset manual es siempre una decision consciente del host: se borra el
# marcador para que start.sh no interprete esto como "el host cambio" y tire
# los datos dos veces.
rm -f .authlab-host.last

echo "==> Levantando de cero con el realm preimportado"
# AUTHLAB_HOST se hereda del entorno si el usuario lo exportó. Si no, start.sh
# vuelve a su valor por defecto (localhost).
exec ./start.sh
