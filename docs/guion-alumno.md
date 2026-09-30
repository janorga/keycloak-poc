# Guía del alumno — AuthLab

Cinco ejercicios. Todos se resuelven con el navegador y las pantallas de la demo.
No hace falta tocar la consola de Keycloak ni escribir código.

**Para empezar:** entra en `http://localhost:9090` con `ana` / `ana`.

| Usuario | Contraseña | Roles |
|---|---|---|
| `ana` | `ana` | `admin`, `user` |
| `luis` | `luis` | `user` |

---

## Ejercicio 1 — Las dos URLs

En la portada hay dos URLs de Keycloak:

- `http://keycloak:8080/realms/lab`
- `http://localhost:8080/realms/lab`

1. ¿Cuál de las dos aparece en la barra de direcciones cuando inicias sesión?
2. ¿Por qué la otra también existe y está en `config_compose.yaml.template`?
3. Imagina que alguien "arregla" el error y pone
   `redirect_uri=http://keycloak:8080/...`. ¿Qué falla, y en quién?

<details><summary>Ver respuesta</summary>

1. `http://localhost:8080/...`, porque la resuelve el **navegador**, que está en tu portátil.
2. Porque la usan los **contenedores**: `main-app` y `resource-server` se llaman
   entre sí por la red interna de docker, donde `keycloak` sí es un nombre válido.
3. El **navegador** no puede resolver `keycloak`: da error de DNS al logar in.
   El servidor seguiría funcionando perfectamente, por eso el fallo desconcierta:
   todo está bien "por dentro" y solo se rompe la pantalla.

</details>

---

## Ejercicio 2 — Anatomía del token

Haz login como `ana` y ve a `/station/jwt`.

1. Pega el access token en <https://jwt.io>. ¿Coincide con lo que ves en pantalla?
2. ¿Cuánto dura el token? Busca `exp` y `iat`.
3. ¿Qué diferencia hay entre el `id_token` y el `access_token`?
4. Localiza `aud`. ¿Qué API acepta este token?

<details><summary>Ver respuesta</summary>

1. Sí, es el mismo contenido. La pantalla decodifica el payload en local, sin
   verificar nada.
2. `exp - iat = 60` segundos. Es intencionadamente corto, para poder enseñar el refresh.
3. El **`id_token`** dice **quién** es el usuario: es para la aplicación.
   El **`access_token`** dice **qué** puede hacer: es para la API.
   Ojos: mandarlos al sitio equivocado es una fuga de datos clásica.
4. `aud` contiene `api-resource`. Lo normal sería que el token valiera para
   cualquier API, pero el *audience mapper* lo restringe. Un token robado de
   nuestra app **no** sirve para la API de al lado.

</details>

---

## Ejercicio 3 — Pedir más es recibir más

1. Haz login normal como `ana` y anota qué hay en `scope`.
2. Pulsa **"1. Cerrar sesión local"**. Si te saltas este paso, el login siguiente
   no te pedirá credenciales (Keycloak ya te reconoce) y el diff no se calculará.
3. Pulsa **"2. Login con scope: openid demo-perfil"**, entra como `ana`.
4. Vuelve a `/station/jwt` y mira el diff.
5. ¿Qué claim ha aparecido? ¿Y quién decide su valor?

<details><summary>Ver respuesta</summary>

1. `openid basic-profile roles`
2. Hecho.
3. Hecho.
4. Ha aparecido **`demo_perfil`**. El diff también muestra que `jti` y `scope`
   cambian en cada login, porque es un token nuevo con otro contenido.
5. Lo decide el **servidor de autorización**, en el *protocol mapper* del
   client scope `demo-perfil`. La app no lo pidió campo a campo: pidió un
   *scope*, y Keycloak correspondingly amplió el token.
   La lección: **el scope es una petición de datos**, no un interruptor de todo o nada.

</details>

---

## Ejercicio 4 — Autenticado no es autorizado

1. Con `ana` en sesión, abre `/station/roles`. Anota los dos códigos.
2. Haz logout. Entra como `luis` / `luis`. Vuelve a `/station/roles`.
3. ¿Ha cambiado la validez del token de Luis? Mira `exp`.
4. ¿Qué claim y qué endpoint explican la diferencia?
5. ¿Qué pasaría si el resource server comprobara el nombre de usuario en vez del rol?

<details><summary>Ver respuesta</summary>

1. `user-only` → **200**, `admin-only` → **200**
2. Hecho.
3. **No.** El token de Luis es tan válido como el de Ana: misma firma, sin
   caducar. Lo que cambia es su contenido.
4. El claim `realm_access.roles` y el endpoint `/api/admin-only`.
   Ana: `["admin","user"]` → le falta `admin` → **403**.
5. Sería un desastre. Habría que tocar el código cada vez que entra o sale
   alguien. Con roles, el cambio es **configuración**: se le añade `admin` a
   Luis en Keycloak y funciona, sin desplegar nada.
   Regla: **el código decide la regla, la configuración decide quién la cumple.**

</details>

---

## Ejercicio 5 — OAuth2 no es login

1. Haz login con el botón **"Login SIN `openid`"** como `ana`.
2. ¿Ha emitido Keycloak un `id_token`?
3. ¿Qué devuelve `/userinfo` con ese token?
4. Explica con tus palabras por qué un `access_token` sin `openid` no puede
   usarse para dar la bienvenida a alguien.

<details><summary>Ver respuesta</summary>

1. (después de pulsar el botón y entrar)
2. **No.** Fíjate en las claves de la respuesta del token endpoint: hay
   `access_token` y `refresh_token`, pero no `id_token`.
3. **403 Forbidden**, sin cuerpo.
4. Porque el `access_token` sin `openid` responde a "¿puede esta app leer tus
   datos?", no a "¿quién eres?". Puede abrir una puerta, pero no tiene un
   nombre detrás. La información de identidad viene en el `id_token`, y sin
   `openid` en el scope **ese token no existe**.

**Extra — PKCE (opcional).** Entra por `/station/pkce` y compara la fase 4 con
la del login normal. Este cliente no tiene `client_secret`, así que su única
barrera es el `code_verifier`. Explica qué impediría a un atacante que
interceptase el `code`. Y cuidado con la conclusión fácil: PKCE no es cosa de
clientes públicos, OAuth 2.1 lo exige a todos.

<details><summary>Ver respuesta</summary>

El atacante que se quede con el `code` no puede canjearlo: el servidor solo
acepta un `code_verifier` cuyo SHA-256 sea el `code_challenge` que él envió.
Encontrar un valor que dé ese hash es computacionalmente inviable. Es la misma
idea que un hash de contraseña, pero aplicada a una petición en vuelo.

</details>

---

## Para después de clase

Tres cosas que en una demo de 55 minutos se quedan fuera y que seguro te
interesan:

- **Rotación de refresh tokens** y detección de robo: Keycloak puede reemitir el
  refresh token en cada uso y detectar cuál de los dos se está reutilizando.
- **Tokens opacos** frente a JWT: un JWT se puede leer sin_llamar al servidor.
  Un token opaco no, pero obliga a una llamada por cada petición.
- **Resource server independiente**: aquí la API vive en su propio contenedor.
  En la vida real la verifica, y muchas veces no emite tokens: solo los valida.
