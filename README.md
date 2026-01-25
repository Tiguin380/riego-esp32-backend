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
              "{\"device_code\":\"RIEGO_001\",\"temperature\":%.2f,\"humidity\":%.2f,\"soil_voltage\":%.2f,\"rain_level\":%.2f,\"humidity_low_threshold\":%.2f,\"valve_state\":\"%s\"}",
              id(temperature_sensor).state, id(soil_hum).state, id(soil_raw).state, id(lluvia_test).state, id(humidity_low).state, (id(valve_relay).state ? "ON" : "OFF")
            );
            return std::string(json);
```

## Uso del Dashboard

Una vez desplegado el backend y configurado el ESP32, accede al dashboard en: `https://<tu-app>.railway.app/panel/RIEGO_001`

### Sensores en Tiempo Real
- **Temperatura**: Muestra la temperatura ambiente.
- **Humedad**: Porcentaje de humedad del suelo.
- **Lluvia**: Nivel de voltaje del sensor de lluvia.

### Configuración Automática
- **Umbral Humedad Baja**: Define el porcentaje por debajo del cual se considera humedad baja.

Guarda la configuración y espera 10 segundos para que el ESP32 aplique los cambios.

## Necesitas que yo lo haga por ti?
Puedo crear el proyecto en Railway y conectar el repo si me das acceso (invítame como colaborador o comparte un token `RAILWAY_API_KEY` con permisos de deploy). Si prefieres hacerlo tú, sigue los pasos anteriores y dime si quieres que revise los logs y finalice la configuración por ti.

---

