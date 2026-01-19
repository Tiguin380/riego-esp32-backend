# Riego ESP32 Backend

Sistema de control de riego automático con ESP32 y dashboard web en la nube.

## Instalación en Railway

1. **Crea un repo en GitHub** desde este código
2. **Conecta Railway a tu GitHub**
3. **Añade variable de entorno**: `DATABASE_URL`
4. **Despliega**

## Configurar ESP32

Añade al `riego_esp32.yaml`:

```yaml
http_request:

script:
  - id: send_sensor_data
    then:
      - http_request.post:
          url: "https://tu-app.railway.app/api/sensor/data"
          json:
            device_code: "ESP32_RIEGO_001"
            temperature: !lambda 'return id(temp_test).state;'
            humidity: !lambda 'return id(hum_test).state;'
            rain_level: !lambda 'return id(lluvia_test).state;'
            humidity_low_threshold: !lambda 'return id(humidity_low).state;'
            humidity_low_color: !lambda 'return id(color_critical).state;'
            humidity_good_color: !lambda 'return id(color_low).state;'
```

Luego llama el script cada 5 segundos desde automations.

## Acceder al Panel

`https://tu-app.railway.app/panel/ESP32_RIEGO_001`
