# Riego ESP32 Backend

Sistema de control de riego automático con ESP32 y dashboard web en la nube.

## Despliegue en Railway (pasos rápidos) ⚡

1. Crea una cuenta en Railway (https://railway.app) o accede a tu cuenta.
2. En Railway crea un nuevo proyecto y añade PostgreSQL (Provision Database).
3. Conecta Railway a tu repositorio de GitHub (Integrations) y selecciona este repo.
4. Añade los secretos en GitHub (Settings → Secrets → Actions):
   - `RAILWAY_API_KEY` = tu API key (token personal) de Railway
   - `RAILWAY_PROJECT_ID` = (opcional) ID del proyecto Railway
5. Railway normalmente creará `DATABASE_URL` automáticamente cuando añades PostgreSQL. Confirma que `DATABASE_URL` está presente en Environment variables del proyecto.
6. (Opcional) Para que las tablas se creen al arrancar el contenedor, añade `AUTO_DB_INIT=true` en Environment variables.
7. Haz push a `main`; el workflow `.github/workflows/deploy-railway.yml` se encargará del despliegue.

### Autoinicialización de la base de datos ✅
El servidor ejecuta automáticamente la creación de tablas al arrancar si existe `DATABASE_URL` o si `AUTO_DB_INIT=true`. Esto evita tener que llamar manualmente a `/api/init` después del despliegue.

### Cuentas de usuario (multi-tenant) 🔐

El backend soporta registro/login y separación de dispositivos por usuario.

- `REQUIRE_USER_LOGIN`:
  - Por defecto es `true` cuando existe `DATABASE_URL` (producción).
  - Si lo pones a `false`, el panel vuelve a modo "abierto" como antes.
- `JWT_SECRET` (recomendado): secreto para firmar la cookie de sesión.
- `ADMIN_KEY` (recomendado): habilita endpoints admin (rotar tokens, obtener claim_token, etc.).

### Emails (confirmación y reset) ✉️

El backend puede enviar:
- Email de confirmación al registrarse (`/verify-email?token=...`).
- Email de recuperación de contraseña (`/reset-password?token=...`).

Variables necesarias (Railway → Variables):
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_FROM` (ej: `AgroSense <no-reply@tudominio.com>`)
- (Opcional) `SMTP_USER`, `SMTP_PASS`
- (Opcional) `SMTP_SECURE` (`true` para 465)
- (Opcional) `PUBLIC_BASE_URL` (ej: `https://<tu-app>.railway.app`) para construir enlaces correctos detrás de proxy
- (Opcional) `PASSWORD_RESET_MINUTES` (por defecto 60)

**Flujo recomendado para comercializar**

1. El usuario entra en `/login` y crea cuenta.
2. Para añadir un ESP32 a su cuenta, usa “+ Añadir dispositivo” y pega el token del dispositivo.
3. A partir de ahí, `/api/devices` y el panel sólo muestran los dispositivos del usuario.

**Emparejamiento (Opción B - simple, sin admin)**

- El backend acepta que el token del dispositivo sea el mismo que usa el ESP32 en la cabecera `X-Device-Token` (en ESPHome: `device_token`).
- Ese mismo token se puede usar como “código de emparejamiento” en la pantalla “Añadir dispositivo”.
- Además, el backend auto-provisiona el dispositivo cuando el ESP32 envía datos por primera vez (crea el registro en `devices` si no existe).

**¿Dónde saco el `device_code` y el `device_token`?**

- `device_code`: es el “nombre/código” del equipo. En este repo está en `substitutions.device_code` (por defecto `RIEGO_001`). Normalmente también se pone en una etiqueta del dispositivo.
- `device_token`: es un secreto compartido. No lo genera la web: lo defines tú (en `secrets.yaml` local) y ese mismo valor se pega en “Añadir dispositivo”.
- Requisitos: mínimo 12 caracteres y NO puede ser `CAMBIA_ESTE_TOKEN`.

### Multi-ESP32 (tokens distintos por dispositivo) ✅

Este repo soporta múltiples ESP32 con tokens distintos **sin** subir secretos a Git:

- Config común: [riego_esp32_base.yaml](riego_esp32_base.yaml)
- Archivos por dispositivo: en la raíz del repo (para que todos usen el mismo `secrets.yaml`)
  - Ejemplo: [riego_esp32_RIEGO_001.yaml](riego_esp32_RIEGO_001.yaml)

En tu `secrets.yaml` (local, ignorado por git) pon un token por dispositivo, por ejemplo:

```yaml
device_token_RIEGO_001: "<token-largo>"
device_token_RIEGO_002: "<token-largo>"
```

Luego, cada archivo de `devices/` referencia su secreto:

```yaml
device_token: !secret device_token_RIEGO_001
```

Compilar/subir:

```bash
esphome compile riego_esp32_RIEGO_001.yaml
esphome upload riego_esp32_RIEGO_001.yaml --device <IP-o-hostname>
```

Generar un token recomendado (64 chars hex):

```bash
npm run gen:device-token
```

**Provisioning (admin)**

- Obtener/rotar `claim_token`:
  - `GET /api/admin/device-claim/:device_code` (header `x-admin-key: <ADMIN_KEY>`)
  - `GET /api/admin/device-claim/:device_code?rotate=true` (rota el token)

### Scripts útiles
- `scripts/railway-deploy-and-init.sh`: despliega usando Railway CLI (usa `RAILWAY_API_KEY` y opcionalmente `RAILWAY_PROJECT_ID`).

## Configurar ESP32

Actualiza la URL en `riego_esp32.yaml` para apuntar a tu app desplegada en Railway:

```yaml
script:
  - id: send_sensor_data
    then:
      - http_request.post:
          url: "https://<tu-app>.railway.app/api/sensor/data"
          request_headers:
            Content-Type: application/json
          body: !lambda |-
            char json[512];
            snprintf(json, sizeof(json),
              "{\"device_code\":\"RIEGO_001\",\"temperature\":%.2f,\"humidity\":%.2f,\"soil_voltage\":%.2f,\"rain_level\":%.2f,\"humidity_low_threshold\":%.2f,\"valve_state\":\"%s\",\"humidity_low_color\":\"%s\",\"humidity_good_color\":\"%s\"}",
              id(temperature_sensor).state, id(soil_hum).state, id(soil_raw).state, id(lluvia_test).state, id(humidity_low).state, (id(valve_relay).state ? "ON" : "OFF"), id(color_critical).state.c_str(), id(color_low).state.c_str()
            );
            return std::string(json);
```

## Uso del Dashboard

Una vez desplegado el backend y configurado el ESP32:

- En modo multi-usuario: entra en `https://<tu-app>.railway.app/` (redirige a `/login` si no hay sesión).
- En modo abierto (si `REQUIRE_USER_LOGIN=false`): `https://<tu-app>.railway.app/panel/RIEGO_001`

### Sensores en Tiempo Real
- **Gráfica en tiempo real**: Muestra Temperatura, Humedad y Lluvia en una gráfica que se actualiza cada 5 segundos con las últimas 20 lecturas.

### Control de LEDs
- Los LEDs se controlan desde la configuración automática (modo automático o manual).
- **Modo Automático**: Los LEDs cambian de color basado en el umbral de humedad configurado.
- **Modo Manual**: Control directo del color de los LEDs.

### Estadísticas (Últimas 24h)
- **Temp Promedio**: Promedio de temperatura en las últimas 24 horas.
- **Temp Máxima**: Temperatura máxima registrada.
- **Temp Mínima**: Temperatura mínima registrada.
- **Humedad Promedio**: Promedio de humedad en las últimas 24 horas.
- **Total Lecturas**: Número total de lecturas en las últimas 24 horas.

Las estadísticas se actualizan automáticamente cada 30 segundos.

## Necesitas que yo lo haga por ti?
Puedo crear el proyecto en Railway y conectar el repo si me das acceso (invítame como colaborador o comparte un token `RAILWAY_API_KEY` con permisos de deploy). Si prefieres hacerlo tú, sigue los pasos anteriores y dime si quieres que revise los logs y finalice la configuración por ti.

---

