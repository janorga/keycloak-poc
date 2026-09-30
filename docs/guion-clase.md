# Guion de clase — AuthLab (55 min)

Demo de OAuth2 + OIDC con Keycloak. Enfoque **conceptual**: la pregunta no es
"cómo configuro esto", sino **por qué existe cada pieza**.

Antes de empezar: `./start.sh` en el portátil, con red. Si algo falla, `./reset.sh -y`.

### Si el stack no está en tu portátil

Toda la clase funciona igual servida desde una VM o un equipo compartido. Solo
cambia el arranque:

```bash
AUTLAB_HOST=192.168.1.50 ./start.sh   # la IP o el dominio que vera el alumno
```

La pantalla de inicio, los enlaces y las URLs que se muestran salen ya con ese
host. Al arrancar te dice por pantalla contra qué host se montó, y si el issuer
que emite Keycloak no coincide con ese host te avisa **antes** de que entre el
primer alumno.

Cambiar de host con el stack ya levantado tira los datos de Keycloak y reimporta
el realm, porque Keycloak solo importa un realm que no existe y el anterior
seguiría teniendo las redirect URIs del host viejo. Tarda unos segundos más y lo
dice por pantalla.

---

## Min 0–5 · Estación 0 — Arranque

`http://localhost:9090`

La pantalla ya tiene las credenciales y los roles de cada usuario. No escribir
nada en la consola de Keycloak: el realm se importa solo.

Di esto en voz alta:

> "Todo lo que veis está arrancado. El realm `lab` se ha importado de un fichero
> JSON. Nadie ha hecho clic en la consola."

Señala las dos URLs del centro:

| | Valor | Quién la usa |
|---|---|---|
| `internal_url` | `http://keycloak:8080/realms/lab` | los contenedores |
| `public_url` | `http://localhost:8080/realms/lab` | el navegador |

> "`keycloak` es un nombre de DNS que existe **solo dentro de la red de docker**.
> Si construyesis la redirección del login con `internal_url`, el navegador
> recibiría `http://keycloak:8080/...` y no podría resolverlo. Es el error más
> caro de esta demo y lo vamos a ver dos veces más."

---

## Min 5–15 · Estación 1 — El flujo en cuatro patas

`/station/flow` — **con una sesión ya iniciada** (haz login como `ana` antes).

Las cuatro patas, con las URLs literales de tu propio login:

1. El navegador pide `/login` a la app.
2. La app **redirige** a Keycloak con `client_id`, `scope`, `state`, `nonce`.
3. El usuario se autentica. Keycloak redirige con un **authorization code**.
4. La app cambia el code por tokens en el **back channel**.

Insiste en tres cosas:

- **El code no es un token.** Es un sobre cerrado. La app no puede leer nada con él.
- **La pata 4 no pasa por el navegador.** Si se pudiera ver, el `client_secret`
  viajaría por el cable del portátil.
- **`state` y `nonce` van y vuelven.** `state` ata la respuesta a *este* navegador
  (evita CSRF). `nonce` ata el `id_token` a *esta* sesión.

> "Si os fijáis, la app manda `redirect_uri=http://localhost:9090/callback`.
> Es la URL **pública**. Keycloak rechaza cualquier redirect que no esté
> literally en la lista del cliente. No hay comodines."

---

## Min 15–25 · Estación 2 — Anatomía del JWT

`/station/jwt`

Muestra las tres partes separadas y recuerda:

> "Header y payload están en **base64url, que no es cifrado**. Cualquiera que
> tenga el token puede leerlo. Lo único que impide editarlo es la firma, y para
> verificarla hay que traer la clave pública de Keycloak.
> Esta pantalla **no verifica**: solo mira. El resource server, que es el que
> de verdad decide algo, sí verifica."

Recorre la tabla de claims. Detente en dos:

- **`aud`** → `api-resource`. Lo escribe el *audience mapper* del cliente.
  Dice **para qué API** es el token.
- **`realm_access.roles`** → `admin, user`. Dice **qué puede hacer**.

### El token entero (el momento "mira, es esto")

Hay un bloque plegable arriba: **"El access_token entero"**.

Ábrelo y pide a un alumno que lea en voz alta los dos puntos que separan las tres
partes. Luego:

1. Pulsa **Copiar** y ábrelo en [jwt.io](https://jwt.io) en otra pestaña. Es el
   mismo token, pero fuera de tu página.
2. En jwt.io, **cambia un carácter del payload** y pulsa Decode. Verás que la
   firma deja de validar.

> "Esto no es un truco de la demo. Es literalmente lo que lleva el navegador en
> la cookie: el `access_token` viaja ahí, firmado pero **sin cifrar**. Por eso
> las DevTools bastan para leerlo, y por eso `openid`Connect exige HTTPS."

Tienes también el enlace **"Abrir en jwt.io"**, que ya lleva el token dentro.
Úsalo si la clase va con prisas; si no, mejor el botón de copiar, porque el
alumno ve el gesto.

### El diff (parte más rentable de la estación)

Ojo con la secuencia: **no basta con pulsar login otra vez.** Si la sesión de
Keycloak sigue abierta, el segundo login te devuelve al instante sin pedirte
nada y el diff nunca se calcula. Hay que cerrar la sesión local primero.

1. Con la sesión actual, la tabla de abajo pide un segundo login.
2. Pulsa **"1. Cerrar sesión local"**. Ojo al nombre: **no** cierra tu sesión
   en Keycloak, solo la de la app. Si usaras el logout completo, tendrías que
   volver a teclear las credenciales y perderías tiempo.
3. Pulsa **"2. Login con scope: openid demo-perfil"** y entra como `ana`.
4. Vuelve a `/station/jwt`.

Sale: **Anadidos (1) → `demo_perfil`**, Quitados (0), Cambiados (2) → `scope` y
`jti`.

> "Pedimos **un scope más** y el token trae **un claim más**: `demo_perfil`.
> Eso es todo. Nada de la app ha cambiado. El scope es la petición de datos,
> y el claim es la respuesta. Nadie ha creado ese campo a mano."

Si alguien pregunta por qué el botón dice "no cierres la de Keycloak": es
precisamente el comportamiento de SSO. Keycloak tiene tu sesión abierta, así que
reconoce quién eres y no te pide credenciales. El logout completo es lo que
rompe esa continuidad.

---

## Min 25–35 · Estación 3 — OAuth2 no es login

**Antes:** haz logout. Luego pulsa **"Login SIN openid"** como `ana`. Vuelve a
`/station/not-login`.

La diferencia respecto a todo lo anterior es **una palabra**: `openid`.

| | Con `openid` | Sin `openid` |
|---|---|---|
| `id_token` | sí | **no** |
| `/userinfo` | 200 + claims | **403** |

Arriba de la pantalla hay dos bloques plegables: **access_token** e **id_token**.
Esta es la parte visual de la tabla. Hazlo así:

1. Estás **sin** `openid`: solo se ve el `access_token`, y debajo un aviso que
   explica que la ausencia del `id_token` **es el objetivo de la estación**.
2. Di: "este token de aquí es todo lo que OAuth2 puro te da".
3. Pide login con `openid` y vuelve. Ahora aparecen **los dos**, uno al lado del
   otro.

> "Mismo cliente, mismo código, mismos permisos para leer tus datos. Lo único
> que ha cambiado es una palabra en el scope, y de repente **hay alguien
> detrás** del token. Eso, y solo eso, es lo que añade OpenID Connect."

Que el `id_token` aparezca en pantalla junto al `access_token`, con el mismo
formato y el mismo botón de copiar, es lo que hace que la comparación sea obvia
en vez de tener que explicarla.

**Nota de versión para el ponente:** en Keycloak 26.7 el rechazo de `/userinfo`
es un **403**, no un 401. Si tu guion dice 401, corrígelo en voz alta: es una
oportunidad gratis para hablar de `401` (no sé quién eres) frente a
`403` (sé quién eres, pero no puedes).

---

## Min 35–45 · Estación 4 — AuthN ≠ AuthZ

Sesión de `ana` → `/station/roles`.

Los dos endpoints reciben **el mismo token**:

```
GET /api/user-only   ->  200 OK
GET /api/admin-only  ->  200 OK
```

Ahora: logout, login como **`luis`** (`luis` / `luis`, rol `user` solamente),
vuelve a `/station/roles`.

```
GET /api/user-only   ->  200 OK
GET /api/admin-only  ->  403 Forbidden
```

> "Luis está **autenticado**. Su token es perfectamente válido: la firma está
> bien, no ha caducado. Lo que falla es la **autorización**.
> Autenticación = quién eres. Autorización = qué te dejan hacer.
> El token no lleva la respuesta: lleva el *material* (`realm_access.roles`)
> para que cada API decida la suya."

Señala el JSON del 403: `required_role: admin`, `roles: [user]`.

> "El resource server no ha hardcodeado nombres de usuario. No tiene ni idea de
> que existe alguien llamado Luis. Solo lee un array de roles."

### El refresh (si sobra tiempo dentro de esta estación)

El access token dura **60 segundos a propósito**. Espera y vuelve a pulsar.

> "No os pido que hagáis nada. La app ha comprobado que el token caducaba, ha
> usado el `refresh_token` por el back channel, y ha seguido. El navegador ni
> se ha enterado. Por eso el access token puede ser tan corto."

---

## Min 45–55 · Cierre

Resumen en tres frases:

1. **OAuth2 es delegación de acceso.** OIDC es lo que le añade identidad.
2. **El token no es una credencial: es una afirmación firmada** sobre quién eres
   y qué puede hacer, con fecha de caducidad.
3. **Autenticado no es lo mismo que autorizado.**

### Bonus (elige uno según el tiempo)

- **PKCE** (`/station/pkce`): login con el cliente público. Un móvil no puede
  guardar un secreto, así que en vez de un secreto se manda una prueba: el
  navegador genera un `code_verifier`, envía su SHA-256 (`code_challenge`) y
  luego demuestra que sabe el original. Si alguien roba el `code`, no puede
  canjearlo: le faltan 256 bits.
- **Mapper en vivo**: en la consola de Keycloak (en otra pestaña), abre
  *Clients → web-confidential → Protocol mappers*, edita el de audience, y vuelve
  a hacer login. El claim `aud` ha cambiado sin tocar una línea de código.
  Enseña que la configuración de permisos **es código**.

### Preguntas que suelen salir

- *"¿Y si alguien roba el access token?"* → Caduca en 60 s, y solo sirve para
  la API que indica `aud`.
- *"¿Por qué no verificamos la firma en la app?"* → Porque aquí solo mostramos.
  En producción, verifica: el resource server lo hace.
- *"¿Y el refresh token?"* → Es de larga duración, así que va protegido: en
  producción se suele mandar por cookie `HttpOnly` y SameSite.

---

## Plan B

Si algo se rompe en directo:

- `./reset.sh -y` devuelve todo al estado inicial en ~40 s.
- Si la **consola de administración** resultara inservible, el laboratorio no
  depende de ella: ninguna estación exige hacer clic dentro.
- Los cuatro valores que importan están en `config_compose.yaml.template`, arriba del todo.
