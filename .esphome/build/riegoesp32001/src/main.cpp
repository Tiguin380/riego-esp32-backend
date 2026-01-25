// Auto generated code by esphome
// ========== AUTO GENERATED INCLUDE BLOCK BEGIN ===========
#include "esphome.h"
using namespace esphome;
using std::isnan;
using std::min;
using std::max;
using namespace number;
using namespace select;
using namespace display;
using namespace sensor;
using namespace light;
using namespace switch_;
using namespace button;
logger::Logger *logger_logger_id;
web_server_base::WebServerBase *web_server_base_webserverbase_id;
wifi::WiFiComponent *wifi_wificomponent_id;
mdns::MDNSComponent *mdns_mdnscomponent_id;
esphome::ESPHomeOTAComponent *esphome_esphomeotacomponent_id;
safe_mode::SafeModeComponent *safe_mode_safemodecomponent_id;
api::APIServer *api_apiserver_id;
using namespace api;
web_server::WebServer *web_server_webserver_id;
const uint8_t ESPHOME_WEBSERVER_INDEX_HTML[174] PROGMEM = {60, 33, 68, 79, 67, 84, 89, 80, 69, 32, 104, 116, 109, 108, 62, 60, 104, 116, 109, 108, 62, 60, 104, 101, 97, 100, 62, 60, 109, 101, 116, 97, 32, 99, 104, 97, 114, 115, 101, 116, 61, 85, 84, 70, 45, 56, 62, 60, 108, 105, 110, 107, 32, 114, 101, 108, 61, 105, 99, 111, 110, 32, 104, 114, 101, 102, 61, 100, 97, 116, 97, 58, 62, 60, 47, 104, 101, 97, 100, 62, 60, 98, 111, 100, 121, 62, 60, 101, 115, 112, 45, 97, 112, 112, 62, 60, 47, 101, 115, 112, 45, 97, 112, 112, 62, 60, 115, 99, 114, 105, 112, 116, 32, 115, 114, 99, 61, 34, 104, 116, 116, 112, 115, 58, 47, 47, 111, 105, 46, 101, 115, 112, 104, 111, 109, 101, 46, 105, 111, 47, 118, 50, 47, 119, 119, 119, 46, 106, 115, 34, 62, 60, 47, 115, 99, 114, 105, 112, 116, 62, 60, 47, 98, 111, 100, 121, 62, 60, 47, 104, 116, 109, 108, 62};
const size_t ESPHOME_WEBSERVER_INDEX_HTML_SIZE = 174;
using namespace i2c;
i2c::IDFI2CBus *i2c_idfi2cbus_id;
using namespace json;
preferences::IntervalSyncer *preferences_intervalsyncer_id;
http_request::HttpRequestIDF *http_request_httprequestidf_id;
script::SingleScript<> *send_sensor_data;
script::SingleScript<> *fetch_config_from_server;
Automation<> *automation_id;
http_request::HttpRequestSendAction<> *http_request_httprequestsendaction_id;
template_::TemplateNumber *humidity_low;
template_::TemplateSelect *color_critical;
template_::TemplateSelect *color_low;
template_::TemplateSelect *color_manual;
font::Font *oled_font;
ssd1306_i2c::I2CSSD1306 *oled_test;
adc::ADCSensor *soil_raw;
sensor::MultiplyFilter *sensor_multiplyfilter_id;
esp32::ESP32InternalGPIOPin *esp32_esp32internalgpiopin_id;
template_::TemplateSensor *soil_hum;
adc::ADCSensor *lluvia_test;
sensor::MultiplyFilter *sensor_multiplyfilter_id_2;
esp32::ESP32InternalGPIOPin *esp32_esp32internalgpiopin_id_2;
esp32_rmt_led_strip::ESP32RMTLEDStripLightOutput *esp32_rmt_led_strip_esp32rmtledstriplightoutput_id;
light::AddressableLightState *rgb_test;
gpio::GPIOSwitch *valve_relay;
esp32::ESP32InternalGPIOPin *esp32_esp32internalgpiopin_id_3;
interval::IntervalTrigger *interval_intervaltrigger_id;
Automation<> *automation_id_5;
script::ScriptExecuteAction<script::Script<>> *script_scriptexecuteaction_id;
interval::IntervalTrigger *interval_intervaltrigger_id_2;
Automation<> *automation_id_6;
script::ScriptExecuteAction<script::Script<>> *script_scriptexecuteaction_id_2;
template_::TemplateButton *template__templatebutton_id;
button::ButtonPressTrigger *button_buttonpresstrigger_id;
Automation<> *automation_id_7;
LambdaAction<> *lambdaaction_id_3;
template_::TemplateButton *template__templatebutton_id_2;
button::ButtonPressTrigger *button_buttonpresstrigger_id_2;
Automation<> *automation_id_8;
LambdaAction<> *lambdaaction_id_4;
Automation<> *automation_id_4;
http_request::HttpRequestSendAction<> *http_request_httprequestsendaction_id_2;
http_request::HttpRequestResponseTrigger *http_request_httprequestresponsetrigger_id;
Automation<std::shared_ptr<http_request::HttpContainer>, std::string &> *automation_id_2;
LambdaAction<std::shared_ptr<http_request::HttpContainer>, std::string &> *lambdaaction_id;
Trigger<> *trigger_id_2;
Automation<> *automation_id_3;
LambdaAction<> *lambdaaction_id_2;
// ========== AUTO GENERATED INCLUDE BLOCK END ==========="

void setup() {
  // ========== AUTO GENERATED CODE BEGIN ===========
  App.reserve_switch(1);
  App.reserve_sensor(3);
  App.reserve_select(3);
  App.reserve_number(1);
  App.reserve_light(1);
  App.reserve_button(2);
  // network:
  //   enable_ipv6: false
  //   min_ipv6_addr_count: 0
  // esphome:
  //   name: riegoesp32001
  //   comment: Riego automático prueba ESP32
  //   min_version: 2025.7.5
  //   build_path: build\riegoesp32001
  //   friendly_name: ''
  //   platformio_options: {}
  //   includes: []
  //   libraries: []
  //   name_add_mac_suffix: false
  //   debug_scheduler: false
  //   areas: []
  //   devices: []
  App.pre_setup("riegoesp32001", "", "Riego autom\303\241tico prueba ESP32", __DATE__ ", " __TIME__, false);
  App.reserve_components(24);
  // number:
  // select:
  // display:
  // sensor:
  // light:
  // switch:
  // button:
  // logger:
  //   level: DEBUG
  //   id: logger_logger_id
  //   baud_rate: 115200
  //   tx_buffer_size: 512
  //   deassert_rts_dtr: false
  //   task_log_buffer_size: 768
  //   hardware_uart: UART0
  //   logs: {}
  logger_logger_id = new logger::Logger(115200, 512);
  logger_logger_id->create_pthread_key();
  logger_logger_id->init_log_buffer(768);
  logger_logger_id->set_log_level(ESPHOME_LOG_LEVEL_DEBUG);
  logger_logger_id->set_uart_selection(logger::UART_SELECTION_UART0);
  logger_logger_id->pre_setup();
  logger_logger_id->set_component_source("logger");
  App.register_component(logger_logger_id);
  // web_server_base:
  //   id: web_server_base_webserverbase_id
  web_server_base_webserverbase_id = new web_server_base::WebServerBase();
  web_server_base_webserverbase_id->set_component_source("web_server_base");
  App.register_component(web_server_base_webserverbase_id);
  web_server_base::global_web_server_base = web_server_base_webserverbase_id;
  // wifi:
  //   reboot_timeout: 15min
  //   id: wifi_wificomponent_id
  //   domain: .local
  //   power_save_mode: LIGHT
  //   fast_connect: false
  //   enable_btm: false
  //   enable_rrm: false
  //   passive_scan: false
  //   enable_on_boot: true
  //   networks:
  //     - ssid: AvanzaFibra_K733
  //       password: ju4SgPKk
  //       id: wifi_wifiap_id
  //       priority: 0.0
  //   use_address: riegoesp32001.local
  wifi_wificomponent_id = new wifi::WiFiComponent();
  wifi_wificomponent_id->set_use_address("riegoesp32001.local");
  {
  wifi::WiFiAP wifi_wifiap_id = wifi::WiFiAP();
  wifi_wifiap_id.set_ssid("AvanzaFibra_K733");
  wifi_wifiap_id.set_password("ju4SgPKk");
  wifi_wifiap_id.set_priority(0.0f);
  wifi_wificomponent_id->add_sta(wifi_wifiap_id);
  }
  wifi_wificomponent_id->set_reboot_timeout(900000);
  wifi_wificomponent_id->set_power_save_mode(wifi::WIFI_POWER_SAVE_LIGHT);
  wifi_wificomponent_id->set_fast_connect(false);
  wifi_wificomponent_id->set_passive_scan(false);
  wifi_wificomponent_id->set_enable_on_boot(true);
  wifi_wificomponent_id->set_component_source("wifi");
  App.register_component(wifi_wificomponent_id);
  // mdns:
  //   id: mdns_mdnscomponent_id
  //   disabled: false
  //   services: []
  mdns_mdnscomponent_id = new mdns::MDNSComponent();
  mdns_mdnscomponent_id->set_component_source("mdns");
  App.register_component(mdns_mdnscomponent_id);
  // ota:
  // ota.esphome:
  //   platform: esphome
  //   id: esphome_esphomeotacomponent_id
  //   version: 2
  //   port: 3232
  esphome_esphomeotacomponent_id = new esphome::ESPHomeOTAComponent();
  esphome_esphomeotacomponent_id->set_port(3232);
  esphome_esphomeotacomponent_id->set_component_source("esphome.ota");
  App.register_component(esphome_esphomeotacomponent_id);
  // safe_mode:
  //   id: safe_mode_safemodecomponent_id
  //   boot_is_good_after: 1min
  //   disabled: false
  //   num_attempts: 10
  //   reboot_timeout: 5min
  safe_mode_safemodecomponent_id = new safe_mode::SafeModeComponent();
  safe_mode_safemodecomponent_id->set_component_source("safe_mode");
  App.register_component(safe_mode_safemodecomponent_id);
  if (safe_mode_safemodecomponent_id->should_enter_safe_mode(10, 300000, 60000)) return;
  // api:
  //   password: ju4SgPKk
  //   id: api_apiserver_id
  //   port: 6053
  //   reboot_timeout: 15min
  //   batch_delay: 100ms
  //   custom_services: false
  api_apiserver_id = new api::APIServer();
  api_apiserver_id->set_component_source("api");
  App.register_component(api_apiserver_id);
  api_apiserver_id->set_port(6053);
  api_apiserver_id->set_password("ju4SgPKk");
  api_apiserver_id->set_reboot_timeout(900000);
  api_apiserver_id->set_batch_delay(100);
  // web_server:
  //   port: 80
  //   id: web_server_webserver_id
  //   version: 2
  //   enable_private_network_access: true
  //   web_server_base_id: web_server_base_webserverbase_id
  //   include_internal: false
  //   log: true
  //   css_url: ''
  //   js_url: https:oi.esphome.io/v2/www.js
  web_server_webserver_id = new web_server::WebServer(web_server_base_webserverbase_id);
  web_server_webserver_id->set_component_source("web_server");
  App.register_component(web_server_webserver_id);
  web_server_base_webserverbase_id->set_port(80);
  web_server_webserver_id->set_expose_log(true);
  web_server_webserver_id->set_include_internal(false);
  // i2c:
  //   sda: 21
  //   scl: 22
  //   scan: true
  //   id: i2c_idfi2cbus_id
  //   sda_pullup_enabled: true
  //   scl_pullup_enabled: true
  //   frequency: 50000.0
  i2c_idfi2cbus_id = new i2c::IDFI2CBus();
  i2c_idfi2cbus_id->set_component_source("i2c");
  App.register_component(i2c_idfi2cbus_id);
  i2c_idfi2cbus_id->set_sda_pin(21);
  i2c_idfi2cbus_id->set_sda_pullup_enabled(true);
  i2c_idfi2cbus_id->set_scl_pin(22);
  i2c_idfi2cbus_id->set_scl_pullup_enabled(true);
  i2c_idfi2cbus_id->set_frequency(50000);
  i2c_idfi2cbus_id->set_scan(true);
  // json:
  //   {}
  // esp32:
  //   board: esp32dev
  //   framework:
  //     version: 5.3.2
  //     sdkconfig_options: {}
  //     advanced:
  //       compiler_optimization: SIZE
  //       enable_lwip_assert: true
  //       ignore_efuse_custom_mac: false
  //       enable_lwip_mdns_queries: true
  //       enable_lwip_bridge_interface: false
  //     components: []
  //     platform_version: https:github.com/pioarduino/platform-espressif32/releases/download/53.03.13/platform-espressif32.zip
  //     source: pioarduino/framework-espidf@https:github.com/pioarduino/esp-idf/releases/download/v5.3.2/esp-idf-v5.3.2.zip
  //     type: esp-idf
  //   flash_size: 4MB
  //   variant: ESP32
  //   cpu_frequency: 160MHZ
  // preferences:
  //   id: preferences_intervalsyncer_id
  //   flash_write_interval: 60s
  preferences_intervalsyncer_id = new preferences::IntervalSyncer();
  preferences_intervalsyncer_id->set_write_interval(60000);
  preferences_intervalsyncer_id->set_component_source("preferences");
  App.register_component(preferences_intervalsyncer_id);
  // http_request:
  //   verify_ssl: false
  //   timeout: 10s
  //   id: http_request_httprequestidf_id
  //   useragent: ESPHome/2025.7.5 (https:esphome.io)
  //   follow_redirects: true
  //   redirect_limit: 3
  //   buffer_size_rx: 512
  //   buffer_size_tx: 512
  http_request_httprequestidf_id = new http_request::HttpRequestIDF();
  http_request_httprequestidf_id->set_timeout(10000);
  http_request_httprequestidf_id->set_useragent("ESPHome/2025.7.5 (https://esphome.io)");
  http_request_httprequestidf_id->set_follow_redirects(true);
  http_request_httprequestidf_id->set_redirect_limit(3);
  http_request_httprequestidf_id->set_buffer_size_rx(512);
  http_request_httprequestidf_id->set_buffer_size_tx(512);
  http_request_httprequestidf_id->set_component_source("http_request");
  App.register_component(http_request_httprequestidf_id);
  // script:
  //   - id: send_sensor_data
  //     then:
  //       - http_request.post:
  //           url: https:riego-esp32-backend-production.up.railway.app/api/sensor/data
  //           request_headers:
  //             Content-Type: application/json
  //           body: !lambda "char json[512];\nsnprintf(json, sizeof(json), \n  \"{\\\"device_code\<cont>
  //             \":\\\"RIEGO_001\\\",\\\"temperature\\\":%.2f,\\\"humidity\\\":%.2f,\\\"
  //             soil_voltage\\\":%.2f,\\\"rain_level\\\":%.2f,\\\"humidity_low_threshold\<cont>
  //             \":%.2f,\\\"valve_state\\\":\\\"%s\\\",\\\"humidity_low_color\\\":\\\"%s\<cont>
  //             \",\\\"humidity_good_color\\\":\\\"%s\\\"}\",\n  0.0,\n  id(soil_hum).state,\n
  //             \  id(soil_raw).state,\n  id(lluvia_test).state,\n  id(humidity_low).state,\n
  //             \  (id(valve_relay).state ? \"ON\" : \"OFF\"),\n  id(color_critical).state.c_str(),\n
  //             \  id(color_low).state.c_str()\n);\nreturn std::string(json);"
  //           id: http_request_httprequestidf_id
  //           capture_response: false
  //           max_response_buffer_size: 1000
  //           method: POST
  //         type_id: http_request_httprequestsendaction_id
  //     trigger_id: trigger_id
  //     automation_id: automation_id
  //     mode: single
  //     parameters: {}
  //   - id: fetch_config_from_server
  //     then:
  //       - http_request.get:
  //           url: https:riego-esp32-backend-production.up.railway.app/api/config/RIEGO_001
  //           capture_response: true
  //           max_response_buffer_size: 1024
  //           on_response:
  //             - then:
  //                 - lambda: !lambda |-
  //                     std::string resp_body = body;
  //                     ESP_LOGI("HTTP", "Body length: %d", resp_body.length());
  //                     ESP_LOGI("RAW", "Response: %.200s", resp_body.c_str());
  //   
  //                      Parse humidity_low_threshold robustly (fallback to local value)
  //                     float umbral = id(humidity_low).state;
  //                     {
  //                       std::string key = "\"humidity_low_threshold\"";
  //                       size_t pos = resp_body.find(key);
  //                       if (pos != std::string::npos) {
  //                         size_t colon = resp_body.find(":", pos + key.length());
  //                         if (colon != std::string::npos) {
  //                           size_t start = colon + 1;
  //                           while (start < resp_body.size() && isspace((unsigned char)resp_body[start])) start++;
  //                           if (start < resp_body.size() && resp_body[start] == '"') start++;
  //                           size_t end = start;
  //                           while (end < resp_body.size() && (isdigit((unsigned char)resp_body[end]) || resp_body[end]=='.' || resp_body[end]=='-')) end++;
  //                           if (end > start) {
  //                             umbral = atof(resp_body.substr(start, end - start).c_str());
  //                             ESP_LOGI("CONFIG", "Parsed umbral: %.1f", umbral);
  //                           }
  //                         }
  //                       }
  //                     }
  //   
  //                      Parse humidity_low_color
  //                     std::string color_low = "Rojo";
  //                     std::string search_low = "\"humidity_low_color\":\"";
  //                     size_t pos_l = resp_body.find(search_low);
  //                     if (pos_l != std::string::npos) {
  //                       size_t start_l = pos_l + search_low.length();
  //                       size_t end_l = resp_body.find("\"", start_l);
  //                       if (end_l != std::string::npos) {
  //                         color_low = resp_body.substr(start_l, end_l - start_l);
  //                       }
  //                     }
  //   
  //                      Parse humidity_good_color
  //                     std::string color_good = "Verde";
  //                     std::string search_good = "\"humidity_good_color\":\"";
  //                     size_t pos_g = resp_body.find(search_good);
  //                     if (pos_g != std::string::npos) {
  //                       size_t start_g = pos_g + search_good.length();
  //                       size_t end_g = resp_body.find("\"", start_g);
  //                       if (end_g != std::string::npos) {
  //                         color_good = resp_body.substr(start_g, end_g - start_g);
  //                       }
  //                     }
  //   
  //                      Obtener humedad actual del sensor y voltage
  //                     float humedad_actual = id(soil_hum).state;
  //                     float soil_v = id(soil_raw).state;
  //                     ESP_LOGI("SENSOR", "Soil V: %.2f, Hum: %.1f, Umbral: %.1f", soil_v, humedad_actual, umbral);
  //   
  //                      Hysteresis para evitar toggles rápidos
  //                     float hys = 1.0;  porcentaje
  //                     if (humedad_actual < (umbral - hys)) {
  //                       id(valve_relay).turn_on();
  //                       ESP_LOGI("VALVE", "ABRIENDO VÁLVULA: Hum %.1f < Umbral %.1f", humedad_actual, umbral);
  //                     } else if (humedad_actual > (umbral + hys)) {
  //                       id(valve_relay).turn_off();
  //                       ESP_LOGI("VALVE", "CERRANDO VÁLVULA: Hum %.1f >= Umbral %.1f", humedad_actual, umbral);
  //                     } else {
  //                       ESP_LOGI("VALVE", "SIN CAMBIO: Hum %.1f Umbral %.1f", humedad_actual, umbral);
  //                     }
  //                   type_id: lambdaaction_id
  //               automation_id: automation_id_2
  //               trigger_id: http_request_httprequestresponsetrigger_id
  //           on_error:
  //             - then:
  //                 - logger.log:
  //                     format: ERROR al obtener configuracion
  //                     args: []
  //                     level: DEBUG
  //                     tag: main
  //                     logger_id: logger_logger_id
  //                   type_id: lambdaaction_id_2
  //               automation_id: automation_id_3
  //               trigger_id: trigger_id_2
  //           id: http_request_httprequestidf_id
  //           method: GET
  //         type_id: http_request_httprequestsendaction_id_2
  //     trigger_id: trigger_id_3
  //     automation_id: automation_id_4
  //     mode: single
  //     parameters: {}
  send_sensor_data = new script::SingleScript<>();
  send_sensor_data->set_name("send_sensor_data");
  fetch_config_from_server = new script::SingleScript<>();
  fetch_config_from_server->set_name("fetch_config_from_server");
  automation_id = new Automation<>(send_sensor_data);
  http_request_httprequestsendaction_id = new http_request::HttpRequestSendAction<>(http_request_httprequestidf_id);
  http_request_httprequestsendaction_id->set_url("https://riego-esp32-backend-production.up.railway.app/api/sensor/data");
  http_request_httprequestsendaction_id->set_method("POST");
  http_request_httprequestsendaction_id->set_capture_response(false);
  http_request_httprequestsendaction_id->set_max_response_buffer_size(1000);
  // number.template:
  //   platform: template
  //   name: Humedad Baja
  //   id: humidity_low
  //   min_value: 10.0
  //   max_value: 100.0
  //   step: 1.0
  //   initial_value: 50.0
  //   unit_of_measurement: '%'
  //   restore_value: true
  //   optimistic: true
  //   disabled_by_default: false
  //   mode: AUTO
  //   update_interval: 60s
  humidity_low = new template_::TemplateNumber();
  humidity_low->set_update_interval(60000);
  humidity_low->set_component_source("template.number");
  App.register_component(humidity_low);
  App.register_number(humidity_low);
  humidity_low->set_name("Humedad Baja");
  humidity_low->set_object_id("humedad_baja");
  humidity_low->set_disabled_by_default(false);
  humidity_low->traits.set_min_value(10.0f);
  humidity_low->traits.set_max_value(100.0f);
  humidity_low->traits.set_step(1.0f);
  humidity_low->traits.set_mode(number::NUMBER_MODE_AUTO);
  humidity_low->traits.set_unit_of_measurement("%");
  humidity_low->set_optimistic(true);
  humidity_low->set_initial_value(50.0f);
  humidity_low->set_restore_value(true);
  // select.template:
  //   platform: template
  //   name: Humedad Baja - Color
  //   id: color_critical
  //   icon: mdi:palette
  //   options:
  //     - Rojo
  //     - Verde
  //     - Azul
  //     - Amarillo
  //     - Cian
  //     - Magenta
  //     - Blanco
  //   initial_option: Rojo
  //   restore_value: true
  //   optimistic: true
  //   disabled_by_default: false
  //   update_interval: 60s
  color_critical = new template_::TemplateSelect();
  color_critical->set_update_interval(60000);
  color_critical->set_component_source("template.select");
  App.register_component(color_critical);
  App.register_select(color_critical);
  color_critical->set_name("Humedad Baja - Color");
  color_critical->set_object_id("humedad_baja_-_color");
  color_critical->set_disabled_by_default(false);
  color_critical->set_icon("mdi:palette");
  color_critical->traits.set_options({"Rojo", "Verde", "Azul", "Amarillo", "Cian", "Magenta", "Blanco"});
  color_critical->set_optimistic(true);
  color_critical->set_initial_option("Rojo");
  color_critical->set_restore_value(true);
  // select.template:
  //   platform: template
  //   name: Humedad Buena - Color
  //   id: color_low
  //   icon: mdi:palette
  //   options:
  //     - Rojo
  //     - Verde
  //     - Azul
  //     - Amarillo
  //     - Cian
  //     - Magenta
  //     - Blanco
  //   initial_option: Verde
  //   restore_value: true
  //   optimistic: true
  //   disabled_by_default: false
  //   update_interval: 60s
  color_low = new template_::TemplateSelect();
  color_low->set_update_interval(60000);
  color_low->set_component_source("template.select");
  App.register_component(color_low);
  App.register_select(color_low);
  color_low->set_name("Humedad Buena - Color");
  color_low->set_object_id("humedad_buena_-_color");
  color_low->set_disabled_by_default(false);
  color_low->set_icon("mdi:palette");
  color_low->traits.set_options({"Rojo", "Verde", "Azul", "Amarillo", "Cian", "Magenta", "Blanco"});
  color_low->set_optimistic(true);
  color_low->set_initial_option("Verde");
  color_low->set_restore_value(true);
  // select.template:
  //   platform: template
  //   name: Color Manual LEDs
  //   id: color_manual
  //   icon: mdi:led-on
  //   options:
  //     - Rojo
  //     - Verde
  //     - Azul
  //     - Amarillo
  //     - Cian
  //     - Magenta
  //     - Blanco
  //     - Automático
  //   initial_option: Automático
  //   restore_value: true
  //   optimistic: true
  //   disabled_by_default: false
  //   update_interval: 60s
  color_manual = new template_::TemplateSelect();
  color_manual->set_update_interval(60000);
  color_manual->set_component_source("template.select");
  App.register_component(color_manual);
  App.register_select(color_manual);
  color_manual->set_name("Color Manual LEDs");
  color_manual->set_object_id("color_manual_leds");
  color_manual->set_disabled_by_default(false);
  color_manual->set_icon("mdi:led-on");
  color_manual->traits.set_options({"Rojo", "Verde", "Azul", "Amarillo", "Cian", "Magenta", "Blanco", "Autom\303\241tico"});
  color_manual->set_optimistic(true);
  color_manual->set_initial_option("Autom\303\241tico");
  color_manual->set_restore_value(true);
  // font:
  //   file:
  //     path: c:\Users\gorra\Desktop\Proyecto_macetas\fonts/NotoSans-Regular.ttf
  //     type: local
  //   id: oled_font
  //   size: 12
  //   glyphs:
  //     - ' '
  //     - '!'
  //     - '"'
  //     - '#'
  //     - $
  //     - '%'
  //     - '&'
  //     - ''''
  //     - (
  //     - )
  //     - '*'
  //     - +
  //     - ','
  //     - '-'
  //     - .
  //     - /
  //     - '0'
  //     - '1'
  //     - '2'
  //     - '3'
  //     - '4'
  //     - '5'
  //     - '6'
  //     - '7'
  //     - '8'
  //     - '9'
  //     - ':'
  //     - ;
  //     - <
  //     - '='
  //     - '>'
  //     - '?'
  //     - '@'
  //     - A
  //     - B
  //     - C
  //     - D
  //     - E
  //     - F
  //     - G
  //     - H
  //     - I
  //     - J
  //     - K
  //     - L
  //     - M
  //     - N
  //     - O
  //     - P
  //     - Q
  //     - R
  //     - S
  //     - T
  //     - U
  //     - V
  //     - W
  //     - X
  //     - Y
  //     - Z
  //     - '['
  //     - 
  //     - ']'
  //     - ^
  //     - _
  //     - '`'
  //     - a
  //     - b
  //     - c
  //     - d
  //     - e
  //     - f
  //     - g
  //     - h
  //     - i
  //     - j
  //     - k
  //     - l
  //     - m
  //     - n
  //     - o
  //     - p
  //     - q
  //     - r
  //     - s
  //     - t
  //     - u
  //     - v
  //     - w
  //     - x
  //     - y
  //     - z
  //     - '{'
  //     - '|'
  //     - '}'
  //     - '~'
  //     -  
  //     - ¢
  //     - £
  //     - ¥
  //     - ©
  //     - ®
  //     - °
  //     - ·
  //     - ×
  //     - ÷
  //     - –
  //     - —
  //     - ‘
  //     - ’
  //     - “
  //     - ”
  //     - •
  //     - …
  //     - €
  //     - ™
  //   glyphsets: []
  //   ignore_missing_glyphs: false
  //   bpp: 1
  //   extras: []
  //   raw_data_id: uint8_t_id
  //   raw_glyph_id: font_glyphdata_id
  static const uint8_t uint8_t_id[] PROGMEM = {0x00, 0xFD, 0x80, 0xB6, 0x80, 0x14, 0x29, 0xF9, 0x22, 0x5F, 0xCA, 0x24, 0x48, 0x23, 0xEB, 0x4E, 0x1C, 0xB5, 0xF1, 0x00, 0xC2, 0xA4, 0xA4, 0xAF, 0xB5, 0xD5, 0x25, 0x25, 0x47, 0x70, 0xC8, 0x58, 0x60, 0xF2, 0x9A, 0x8C, 0x8C, 0x73, 0xE0, 0x29, 0x25, 0x92, 0x48, 0x80, 0xC8, 0x92, 0x49, 0x2B, 0x00, 0x10, 0x4F, 0xCC, 0x29, 0xA0, 0x21, 0x3E, 0x42, 0x10, 0x5C, 0xE0, 0xC0, 0x11, 0x22, 0x24, 0x44, 0x80, 0x74, 0x63, 0x18, 0xC6, 0x31, 0x70, 0x2E, 0x92, 0x49, 0x20, 0xF4, 0x42, 0x11, 0x11, 0x10, 0xF8, 0xF4, 0x42, 0x37, 0x04, 0x21, 0xF0, 0x08, 0x30, 0x61, 0x44, 0x89, 0x3F, 0x84, 0x08, 0xFC, 0x21, 0xE0, 0x84, 0x31, 0xF0, 0x3E, 0x21, 0xE8, 0xC6, 0x31, 0x70, 0xF8, 0x46, 0x21, 0x10, 0x88, 0x40, 0x74, 0x63, 0xA7, 0x46, 0x31, 0xF0, 0x74, 0x63, 0x18, 0xBC, 0x22, 0xE0, 0xC6, 0x50, 0x05, 0x80, 0x09, 0xB1, 0xC1, 0x84, 0xF8, 0x01, 0xF0, 0x83, 0x06, 0x6C, 0x40, 0xF0, 0x42, 0x22, 0x10, 0x04, 0x60, 0x3E, 0x20, 0xA7, 0x34, 0x9A, 0x4D, 0x26, 0x6D, 0x00, 0x42, 0x1F, 0x00, 0x10, 0x18, 0x28, 0x24, 0x24, 0x7C, 0x42, 0x42, 0x83, 0xFA, 0x38, 0x63, 0xFA, 0x18, 0x61, 0xF8, 0x3D, 0x18, 0x20, 0x82, 0x08, 0x10, 0x3C, 0xF9, 0x0A, 0x0C, 0x18, 0x30, 0x61, 0xC2, 0xF8, 0xFC, 0x21, 0x0F, 0xC2, 0x10, 0xF8, 0xFC, 0x21, 0x0F, 0xC2, 0x10, 0x80, 0x3E, 0x82, 0x04, 0x08, 0xF0, 0x60, 0xA1, 0x3E, 0x83, 0x06, 0x0C, 0x1F, 0xF0, 0x60, 0xC1, 0x82, 0xF6, 0x66, 0x66, 0x66, 0xF0, 0x24, 0x92, 0x49, 0x24, 0xE0, 0x86, 0x29, 0x28, 0xE2, 0x49, 0xA2, 0x84, 0x84, 0x21, 0x08, 0x42, 0x10, 0xF8, 0xC1, 0xE0, 0xE8, 0xB4, 0x5A, 0x4C, 0xA6, 0x53, 0x31, 0x88, 0x80, 0xC3, 0x86, 0x8D, 0x99, 0x31, 0x63, 0xC3, 0x86, 0x3C, 0x46, 0x82, 0x83, 0x83, 0x83, 0x82, 0x46, 0x3C, 0xFA, 0x28, 0x62, 0xF2, 0x08, 0x20, 0x80, 0x3C, 0x46, 0x82, 0x83, 0x83, 0x83, 0x82, 0x46, 0x3C, 0x0C, 0x06, 0xFA, 0x38, 0x62, 0xF2, 0x48, 0xA2, 0x84, 0x7C, 0x21, 0x87, 0x0C, 0x21, 0xF0, 0xFE, 0x20, 0x40, 0x81, 0x02, 0x04, 0x08, 0x10, 0x83, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xE2, 0x78, 0x82, 0x85, 0x12, 0x22, 0x45, 0x0A, 0x0C, 0x10, 0x84, 0x28, 0xC5, 0x29, 0x25, 0x24, 0xA4, 0x62, 0x8C, 0x61, 0x8C, 0x31, 0x80, 0xC6, 0x88, 0xA1, 0xC1, 0x05, 0x0A, 0x22, 0x86, 0x86, 0x89, 0x31, 0x43, 0x02, 0x04, 0x08, 0x10, 0x7C, 0x10, 0x86, 0x10, 0x82, 0x10, 0xFC, 0xF2, 0x49, 0x24, 0x93, 0x80, 0x84, 0x44, 0x22, 0x21, 0x10, 0xE4, 0x92, 0x49, 0x27, 0x80, 0x10, 0xC2, 0x92, 0x47, 0x10, 0xF8, 0xC4, 0xF0, 0x43, 0xF8, 0xCF, 0xA0, 0x82, 0x08, 0x2E, 0xCA, 0x18, 0x61, 0xCA, 0xE0, 0x78, 0x88, 0x88, 0x70, 0x08, 0x42, 0xF8, 0xC6, 0x31, 0x8B, 0xC0, 0x74, 0x63, 0xF8, 0x41, 0xE0, 0x3B, 0x11, 0xE4, 0x21, 0x08, 0x42, 0x00, 0x7C, 0x63, 0x18, 0xC5, 0xE1, 0x0F, 0x80, 0x84, 0x21, 0x7C, 0xC6, 0x31, 0x8C, 0x40, 0x9F, 0xC0, 0x20, 0x12, 0x49, 0x24, 0x9E, 0x84, 0x21, 0x39, 0x53, 0x96, 0x94, 0x40, 0xFF, 0xC0, 0xBB, 0xE6, 0x62, 0x31, 0x18, 0x8C, 0x46, 0x22, 0xBE, 0x63, 0x18, 0xC6, 0x20, 0x72, 0x28, 0xE1, 0x8E, 0x27, 0x00, 0xBB, 0x28, 0x61, 0x87, 0x2B, 0xA0, 0x82, 0x00, 0x7C, 0x63, 0x18, 0xC5, 0xE1, 0x08, 0x40, 0xBC, 0x88, 0x88, 0x80, 0xF8, 0x86, 0x11, 0xF0, 0x44, 0xF4, 0x44, 0x44, 0x30, 0x8C, 0x63, 0x18, 0xC5, 0xE0, 0x85, 0x34, 0x92, 0x38, 0xC3, 0x00, 0x88, 0xA6, 0x55, 0x2A, 0xA5, 0x32, 0x98, 0x8C, 0xC5, 0x23, 0x0C, 0x31, 0x2C, 0x40, 0x85, 0x34, 0x92, 0x28, 0xC3, 0x08, 0x23, 0x00, 0x78, 0x44, 0x42, 0x23, 0xE0, 0x32, 0x22, 0x2C, 0x22, 0x22, 0x30, 0xFF, 0xF8, 0xC2, 0x22, 0x21, 0x22, 0x22, 0xC0, 0xED, 0xC0, 0x00, 0x23, 0xF1, 0x08, 0x43, 0x0F, 0x20, 0x3C, 0x82, 0x08, 0xF8, 0x82, 0x10, 0xFC, 0xC6, 0x89, 0xA1, 0x43, 0x8F, 0x9F, 0x08, 0x10, 0x3C, 0x42, 0x9D, 0xA1, 0xA1, 0xA1, 0xA1, 0x99, 0x42, 0x3C, 0x3C, 0x42, 0xB9, 0xA5, 0xA5, 0xB9, 0xA9, 0xA5, 0x42, 0x3C, 0xF6, 0xF0, 0xC0, 0x8A, 0x88, 0xA8, 0x80, 0x21, 0x01, 0xF2, 0x10, 0xFC, 0xFF, 0xF0, 0x58, 0x78, 0x55, 0xB0, 0x5D, 0xA0, 0xDF, 0x00, 0x93, 0x9B, 0x1E, 0x41, 0x07, 0xC4, 0x1F, 0x10, 0x10, 0x1C, 0xE9, 0x4D, 0x4F, 0x4F};
  static const font::GlyphData font_glyphdata_id[] = {font::GlyphData{
    .a_char = (const uint8_t *)" ",
    .data = uint8_t_id + 0,
    .advance = 3,
    .offset_x = 0,
    .offset_y = 12,
    .width = 1,
    .height = 1,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"!",
    .data = uint8_t_id + 1,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 4,
    .width = 1,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\042",
    .data = uint8_t_id + 3,
    .advance = 5,
    .offset_x = 1,
    .offset_y = 4,
    .width = 3,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"#",
    .data = uint8_t_id + 5,
    .advance = 8,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"$",
    .data = uint8_t_id + 13,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 3,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"%",
    .data = uint8_t_id + 20,
    .advance = 10,
    .offset_x = 1,
    .offset_y = 4,
    .width = 8,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"&",
    .data = uint8_t_id + 29,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 8,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"'",
    .data = uint8_t_id + 38,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 4,
    .width = 1,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"(",
    .data = uint8_t_id + 39,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 3,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)")",
    .data = uint8_t_id + 44,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 3,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"*",
    .data = uint8_t_id + 49,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 3,
    .width = 6,
    .height = 6,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"+",
    .data = uint8_t_id + 54,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 6,
  }, font::GlyphData{
    .a_char = (const uint8_t *)",",
    .data = uint8_t_id + 58,
    .advance = 3,
    .offset_x = 0,
    .offset_y = 12,
    .width = 2,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"-",
    .data = uint8_t_id + 59,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 9,
    .width = 3,
    .height = 1,
  }, font::GlyphData{
    .a_char = (const uint8_t *)".",
    .data = uint8_t_id + 60,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 11,
    .width = 1,
    .height = 2,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"/",
    .data = uint8_t_id + 61,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"0",
    .data = uint8_t_id + 66,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"1",
    .data = uint8_t_id + 72,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 3,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"2",
    .data = uint8_t_id + 76,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"3",
    .data = uint8_t_id + 82,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"4",
    .data = uint8_t_id + 88,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"5",
    .data = uint8_t_id + 96,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"6",
    .data = uint8_t_id + 102,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"7",
    .data = uint8_t_id + 108,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"8",
    .data = uint8_t_id + 114,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"9",
    .data = uint8_t_id + 120,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)":",
    .data = uint8_t_id + 126,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 6,
    .width = 1,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)";",
    .data = uint8_t_id + 127,
    .advance = 3,
    .offset_x = 0,
    .offset_y = 6,
    .width = 2,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"<",
    .data = uint8_t_id + 130,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 6,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"=",
    .data = uint8_t_id + 134,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 4,
  }, font::GlyphData{
    .a_char = (const uint8_t *)">",
    .data = uint8_t_id + 137,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 6,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"?",
    .data = uint8_t_id + 141,
    .advance = 5,
    .offset_x = 0,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"@",
    .data = uint8_t_id + 147,
    .advance = 11,
    .offset_x = 1,
    .offset_y = 4,
    .width = 9,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"A",
    .data = uint8_t_id + 159,
    .advance = 8,
    .offset_x = 0,
    .offset_y = 4,
    .width = 8,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"B",
    .data = uint8_t_id + 168,
    .advance = 8,
    .offset_x = 1,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"C",
    .data = uint8_t_id + 175,
    .advance = 8,
    .offset_x = 1,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"D",
    .data = uint8_t_id + 182,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"E",
    .data = uint8_t_id + 190,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"F",
    .data = uint8_t_id + 196,
    .advance = 6,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"G",
    .data = uint8_t_id + 202,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"H",
    .data = uint8_t_id + 210,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"I",
    .data = uint8_t_id + 218,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"J",
    .data = uint8_t_id + 223,
    .advance = 3,
    .offset_x = -1,
    .offset_y = 4,
    .width = 3,
    .height = 12,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"K",
    .data = uint8_t_id + 228,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"L",
    .data = uint8_t_id + 235,
    .advance = 6,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"M",
    .data = uint8_t_id + 241,
    .advance = 11,
    .offset_x = 1,
    .offset_y = 4,
    .width = 9,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"N",
    .data = uint8_t_id + 252,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"O",
    .data = uint8_t_id + 260,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 8,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"P",
    .data = uint8_t_id + 269,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"Q",
    .data = uint8_t_id + 276,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 8,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"R",
    .data = uint8_t_id + 287,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"S",
    .data = uint8_t_id + 294,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"T",
    .data = uint8_t_id + 300,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"U",
    .data = uint8_t_id + 308,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"V",
    .data = uint8_t_id + 316,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"W",
    .data = uint8_t_id + 324,
    .advance = 11,
    .offset_x = 0,
    .offset_y = 4,
    .width = 11,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"X",
    .data = uint8_t_id + 337,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"Y",
    .data = uint8_t_id + 345,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"Z",
    .data = uint8_t_id + 353,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"[",
    .data = uint8_t_id + 360,
    .advance = 4,
    .offset_x = 1,
    .offset_y = 4,
    .width = 3,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\134",
    .data = uint8_t_id + 365,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"]",
    .data = uint8_t_id + 370,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 3,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"^",
    .data = uint8_t_id + 375,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 6,
    .height = 6,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"_",
    .data = uint8_t_id + 380,
    .advance = 5,
    .offset_x = 0,
    .offset_y = 14,
    .width = 5,
    .height = 1,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"`",
    .data = uint8_t_id + 381,
    .advance = 3,
    .offset_x = 0,
    .offset_y = 3,
    .width = 3,
    .height = 2,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"a",
    .data = uint8_t_id + 382,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"b",
    .data = uint8_t_id + 387,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 3,
    .width = 6,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"c",
    .data = uint8_t_id + 395,
    .advance = 6,
    .offset_x = 1,
    .offset_y = 6,
    .width = 4,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"d",
    .data = uint8_t_id + 399,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 3,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"e",
    .data = uint8_t_id + 406,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"f",
    .data = uint8_t_id + 411,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 3,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"g",
    .data = uint8_t_id + 418,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"h",
    .data = uint8_t_id + 425,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 3,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"i",
    .data = uint8_t_id + 432,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 3,
    .width = 1,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"j",
    .data = uint8_t_id + 434,
    .advance = 3,
    .offset_x = -1,
    .offset_y = 3,
    .width = 3,
    .height = 13,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"k",
    .data = uint8_t_id + 439,
    .advance = 6,
    .offset_x = 1,
    .offset_y = 3,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"l",
    .data = uint8_t_id + 446,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 3,
    .width = 1,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"m",
    .data = uint8_t_id + 448,
    .advance = 11,
    .offset_x = 1,
    .offset_y = 6,
    .width = 9,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"n",
    .data = uint8_t_id + 456,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"o",
    .data = uint8_t_id + 461,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 6,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"p",
    .data = uint8_t_id + 467,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 6,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"q",
    .data = uint8_t_id + 475,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"r",
    .data = uint8_t_id + 482,
    .advance = 5,
    .offset_x = 1,
    .offset_y = 6,
    .width = 4,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"s",
    .data = uint8_t_id + 486,
    .advance = 6,
    .offset_x = 1,
    .offset_y = 6,
    .width = 4,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"t",
    .data = uint8_t_id + 490,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"u",
    .data = uint8_t_id + 495,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"v",
    .data = uint8_t_id + 500,
    .advance = 6,
    .offset_x = 0,
    .offset_y = 6,
    .width = 6,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"w",
    .data = uint8_t_id + 506,
    .advance = 9,
    .offset_x = 0,
    .offset_y = 6,
    .width = 9,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"x",
    .data = uint8_t_id + 514,
    .advance = 6,
    .offset_x = 0,
    .offset_y = 6,
    .width = 6,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"y",
    .data = uint8_t_id + 520,
    .advance = 6,
    .offset_x = 0,
    .offset_y = 6,
    .width = 6,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"z",
    .data = uint8_t_id + 528,
    .advance = 6,
    .offset_x = 0,
    .offset_y = 6,
    .width = 5,
    .height = 7,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"{",
    .data = uint8_t_id + 533,
    .advance = 5,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"|",
    .data = uint8_t_id + 539,
    .advance = 7,
    .offset_x = 3,
    .offset_y = 3,
    .width = 1,
    .height = 13,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"}",
    .data = uint8_t_id + 541,
    .advance = 5,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 11,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"~",
    .data = uint8_t_id + 547,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 7,
    .width = 5,
    .height = 2,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\240",
    .data = uint8_t_id + 549,
    .advance = 3,
    .offset_x = 0,
    .offset_y = 12,
    .width = 1,
    .height = 1,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\242",
    .data = uint8_t_id + 550,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 4,
    .width = 5,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\243",
    .data = uint8_t_id + 556,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 6,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\245",
    .data = uint8_t_id + 563,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\251",
    .data = uint8_t_id + 571,
    .advance = 10,
    .offset_x = 1,
    .offset_y = 3,
    .width = 8,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\256",
    .data = uint8_t_id + 581,
    .advance = 10,
    .offset_x = 1,
    .offset_y = 3,
    .width = 8,
    .height = 10,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\260",
    .data = uint8_t_id + 591,
    .advance = 5,
    .offset_x = 1,
    .offset_y = 4,
    .width = 3,
    .height = 4,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\302\267",
    .data = uint8_t_id + 593,
    .advance = 3,
    .offset_x = 1,
    .offset_y = 7,
    .width = 1,
    .height = 2,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\303\227",
    .data = uint8_t_id + 594,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 6,
    .width = 5,
    .height = 5,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\303\267",
    .data = uint8_t_id + 598,
    .advance = 7,
    .offset_x = 1,
    .offset_y = 5,
    .width = 5,
    .height = 6,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\223",
    .data = uint8_t_id + 602,
    .advance = 6,
    .offset_x = 0,
    .offset_y = 9,
    .width = 6,
    .height = 1,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\224",
    .data = uint8_t_id + 603,
    .advance = 12,
    .offset_x = 0,
    .offset_y = 9,
    .width = 12,
    .height = 1,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\230",
    .data = uint8_t_id + 605,
    .advance = 2,
    .offset_x = 0,
    .offset_y = 4,
    .width = 2,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\231",
    .data = uint8_t_id + 606,
    .advance = 2,
    .offset_x = 0,
    .offset_y = 4,
    .width = 2,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\234",
    .data = uint8_t_id + 607,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\235",
    .data = uint8_t_id + 609,
    .advance = 4,
    .offset_x = 0,
    .offset_y = 4,
    .width = 4,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\242",
    .data = uint8_t_id + 611,
    .advance = 5,
    .offset_x = 1,
    .offset_y = 7,
    .width = 3,
    .height = 3,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\200\246",
    .data = uint8_t_id + 613,
    .advance = 9,
    .offset_x = 1,
    .offset_y = 11,
    .width = 8,
    .height = 2,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\202\254",
    .data = uint8_t_id + 615,
    .advance = 7,
    .offset_x = 0,
    .offset_y = 4,
    .width = 7,
    .height = 9,
  }, font::GlyphData{
    .a_char = (const uint8_t *)"\342\204\242",
    .data = uint8_t_id + 623,
    .advance = 9,
    .offset_x = 0,
    .offset_y = 4,
    .width = 8,
    .height = 4,
  }};
  oled_font = new font::Font(font_glyphdata_id, 115, 13, 16, 4, 7, 9, 1);
  // display.ssd1306_i2c:
  //   platform: ssd1306_i2c
  //   model: SSD1306_128X64
  //   address: 0x3C
  //   id: oled_test
  //   lambda: !lambda |-
  //      Línea 1: Humedad y voltaje
  //     it.printf(0, 0, id(oled_font), "Humedad: %.1f%% Volt: %.2fV", id(soil_hum).state, id(soil_raw).state);
  //      Línea 2: Umbral configurado
  //     it.printf(0, 16, id(oled_font), "Umbral: %.1f%%", id(humidity_low).state);
  //      Línea 3: Estado válvula
  //     if (id(valve_relay).state) it.printf(0, 32, id(oled_font), "VALVULA: ON "); else it.printf(0, 32, id(oled_font), "VALVULA: OFF");
  //      Línea 4: Lectura lluvia
  //     it.printf(0, 48, id(oled_font), "Lluvia V: %.2f", id(lluvia_test).state);
  //   auto_clear_enabled: unspecified
  //   brightness: 1.0
  //   contrast: 1.0
  //   flip_x: true
  //   flip_y: true
  //   offset_x: 0
  //   offset_y: 0
  //   invert: false
  //   update_interval: 1s
  //   i2c_id: i2c_idfi2cbus_id
  oled_test = new ssd1306_i2c::I2CSSD1306();
  oled_test->set_update_interval(1000);
  oled_test->set_component_source("display");
  App.register_component(oled_test);
  oled_test->set_auto_clear(true);
  oled_test->set_model(ssd1306_base::SSD1306_MODEL_128_64);
  oled_test->init_brightness(1.0f);
  oled_test->init_contrast(1.0f);
  oled_test->init_flip_x(true);
  oled_test->init_flip_y(true);
  oled_test->init_offset_x(0);
  oled_test->init_offset_y(0);
  oled_test->init_invert(false);
  // sensor.adc:
  //   platform: adc
  //   pin:
  //     number: 34
  //     mode:
  //       input: true
  //       output: false
  //       open_drain: false
  //       pullup: false
  //       pulldown: false
  //     id: esp32_esp32internalgpiopin_id
  //     inverted: false
  //     ignore_pin_validation_error: false
  //     ignore_strapping_warning: false
  //     drive_strength: 20.0
  //   name: Soil Voltage
  //   id: soil_raw
  //   update_interval: 5s
  //   filters:
  //     - multiply: 3.3
  //       type_id: sensor_multiplyfilter_id
  //   disabled_by_default: false
  //   force_update: false
  //   unit_of_measurement: V
  //   accuracy_decimals: 2
  //   device_class: voltage
  //   state_class: measurement
  //   raw: false
  //   attenuation: 0db
  //   samples: 1
  //   sampling_mode: avg
  soil_raw = new adc::ADCSensor();
  soil_raw->set_update_interval(5000);
  soil_raw->set_component_source("adc.sensor");
  App.register_component(soil_raw);
  App.register_sensor(soil_raw);
  soil_raw->set_name("Soil Voltage");
  soil_raw->set_object_id("soil_voltage");
  soil_raw->set_disabled_by_default(false);
  soil_raw->set_device_class("voltage");
  soil_raw->set_state_class(sensor::STATE_CLASS_MEASUREMENT);
  soil_raw->set_unit_of_measurement("V");
  soil_raw->set_accuracy_decimals(2);
  soil_raw->set_force_update(false);
  sensor_multiplyfilter_id = new sensor::MultiplyFilter(3.3f);
  soil_raw->set_filters({sensor_multiplyfilter_id});
  esp32_esp32internalgpiopin_id = new esp32::ESP32InternalGPIOPin();
  esp32_esp32internalgpiopin_id->set_pin(::GPIO_NUM_34);
  esp32_esp32internalgpiopin_id->set_inverted(false);
  esp32_esp32internalgpiopin_id->set_drive_strength(::GPIO_DRIVE_CAP_2);
  esp32_esp32internalgpiopin_id->set_flags(gpio::Flags::FLAG_INPUT);
  soil_raw->set_pin(esp32_esp32internalgpiopin_id);
  soil_raw->set_output_raw(false);
  soil_raw->set_sample_count(1);
  soil_raw->set_sampling_mode(adc::SamplingMode::AVG);
  soil_raw->set_attenuation(ADC_ATTEN_DB_0);
  soil_raw->set_channel1(::ADC1_CHANNEL_6);
  // sensor.template:
  //   platform: template
  //   name: Soil Humidity
  //   id: soil_hum
  //   unit_of_measurement: '%'
  //   update_interval: 5s
  //   lambda: !lambda |-
  //     float v = id(soil_raw).state;
  //      Ajusta min_v/max_v según tu sensor y suelo (valores de ejemplo)
  //     float min_v = 0.30;  suelo muy mojado
  //     float max_v = 3.00;  suelo muy seco
  //     if (v < min_v) v = min_v;
  //     if (v > max_v) v = max_v;
  //     float pct = (1.0 - (v - min_v) / (max_v - min_v)) * 100.0;
  //     return pct;
  //   disabled_by_default: false
  //   force_update: false
  //   accuracy_decimals: 1
  soil_hum = new template_::TemplateSensor();
  App.register_sensor(soil_hum);
  soil_hum->set_name("Soil Humidity");
  soil_hum->set_object_id("soil_humidity");
  soil_hum->set_disabled_by_default(false);
  soil_hum->set_unit_of_measurement("%");
  soil_hum->set_accuracy_decimals(1);
  soil_hum->set_force_update(false);
  soil_hum->set_update_interval(5000);
  soil_hum->set_component_source("template.sensor");
  App.register_component(soil_hum);
  soil_hum->set_template([=]() -> esphome::optional<float> {
      #line 242 "c:\\Users\\gorra\\Desktop\\Proyecto_macetas\\riego_esp32.yaml"
      float v = soil_raw->state;
       
      float min_v = 0.30;  
      float max_v = 3.00;  
      if (v < min_v) v = min_v;
      if (v > max_v) v = max_v;
      float pct = (1.0 - (v - min_v) / (max_v - min_v)) * 100.0;
      return pct;
  });
  // sensor.adc:
  //   platform: adc
  //   pin:
  //     number: 35
  //     mode:
  //       input: true
  //       output: false
  //       open_drain: false
  //       pullup: false
  //       pulldown: false
  //     id: esp32_esp32internalgpiopin_id_2
  //     inverted: false
  //     ignore_pin_validation_error: false
  //     ignore_strapping_warning: false
  //     drive_strength: 20.0
  //   name: Lluvia Test
  //   id: lluvia_test
  //   update_interval: 5s
  //   filters:
  //     - multiply: 3.3
  //       type_id: sensor_multiplyfilter_id_2
  //   disabled_by_default: false
  //   force_update: false
  //   unit_of_measurement: V
  //   accuracy_decimals: 2
  //   device_class: voltage
  //   state_class: measurement
  //   raw: false
  //   attenuation: 0db
  //   samples: 1
  //   sampling_mode: avg
  lluvia_test = new adc::ADCSensor();
  lluvia_test->set_update_interval(5000);
  lluvia_test->set_component_source("adc.sensor");
  App.register_component(lluvia_test);
  App.register_sensor(lluvia_test);
  lluvia_test->set_name("Lluvia Test");
  lluvia_test->set_object_id("lluvia_test");
  lluvia_test->set_disabled_by_default(false);
  lluvia_test->set_device_class("voltage");
  lluvia_test->set_state_class(sensor::STATE_CLASS_MEASUREMENT);
  lluvia_test->set_unit_of_measurement("V");
  lluvia_test->set_accuracy_decimals(2);
  lluvia_test->set_force_update(false);
  sensor_multiplyfilter_id_2 = new sensor::MultiplyFilter(3.3f);
  lluvia_test->set_filters({sensor_multiplyfilter_id_2});
  esp32_esp32internalgpiopin_id_2 = new esp32::ESP32InternalGPIOPin();
  esp32_esp32internalgpiopin_id_2->set_pin(::GPIO_NUM_35);
  esp32_esp32internalgpiopin_id_2->set_inverted(false);
  esp32_esp32internalgpiopin_id_2->set_drive_strength(::GPIO_DRIVE_CAP_2);
  esp32_esp32internalgpiopin_id_2->set_flags(gpio::Flags::FLAG_INPUT);
  lluvia_test->set_pin(esp32_esp32internalgpiopin_id_2);
  lluvia_test->set_output_raw(false);
  lluvia_test->set_sample_count(1);
  lluvia_test->set_sampling_mode(adc::SamplingMode::AVG);
  lluvia_test->set_attenuation(ADC_ATTEN_DB_0);
  lluvia_test->set_channel1(::ADC1_CHANNEL_7);
  // light.esp32_rmt_led_strip:
  //   platform: esp32_rmt_led_strip
  //   rgb_order: GRB
  //   pin: 26
  //   num_leds: 4
  //   chipset: WS2812
  //   id: rgb_test
  //   internal: true
  //   restore_mode: ALWAYS_ON
  //   disabled_by_default: false
  //   gamma_correct: 2.8
  //   default_transition_length: 1s
  //   flash_transition_length: 0s
  //   output_id: esp32_rmt_led_strip_esp32rmtledstriplightoutput_id
  //   rmt_symbols: 192
  //   is_rgbw: false
  //   is_wrgb: false
  //   use_psram: true
  //   reset_high: 0us
  //   reset_low: 0us
  //   name: rgb_test
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id = new esp32_rmt_led_strip::ESP32RMTLEDStripLightOutput();
  rgb_test = new light::AddressableLightState(esp32_rmt_led_strip_esp32rmtledstriplightoutput_id);
  App.register_light(rgb_test);
  rgb_test->set_component_source("light");
  App.register_component(rgb_test);
  rgb_test->set_name("rgb_test");
  rgb_test->set_object_id("rgb_test");
  rgb_test->set_disabled_by_default(false);
  rgb_test->set_internal(true);
  rgb_test->set_restore_mode(light::LIGHT_ALWAYS_ON);
  rgb_test->set_default_transition_length(1000);
  rgb_test->set_flash_transition_length(0);
  rgb_test->set_gamma_correct(2.8f);
  rgb_test->add_effects({});
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_component_source("esp32_rmt_led_strip.light");
  App.register_component(esp32_rmt_led_strip_esp32rmtledstriplightoutput_id);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_num_leds(4);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_pin(26);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_led_params(400, 1000, 1000, 400, 0, 0);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_rgb_order(esp32_rmt_led_strip::ORDER_GRB);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_is_rgbw(false);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_is_wrgb(false);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_use_psram(true);
  esp32_rmt_led_strip_esp32rmtledstriplightoutput_id->set_rmt_symbols(192);
  // switch.gpio:
  //   platform: gpio
  //   pin:
  //     number: 25
  //     inverted: true
  //     mode:
  //       output: true
  //       input: false
  //       open_drain: false
  //       pullup: false
  //       pulldown: false
  //     id: esp32_esp32internalgpiopin_id_3
  //     ignore_pin_validation_error: false
  //     ignore_strapping_warning: false
  //     drive_strength: 20.0
  //   id: valve_relay
  //   name: Válvula Riego
  //   restore_mode: ALWAYS_OFF
  //   disabled_by_default: false
  //   interlock_wait_time: 0ms
  valve_relay = new gpio::GPIOSwitch();
  App.register_switch(valve_relay);
  valve_relay->set_name("V\303\241lvula Riego");
  valve_relay->set_object_id("v_lvula_riego");
  valve_relay->set_disabled_by_default(false);
  valve_relay->set_restore_mode(switch_::SWITCH_ALWAYS_OFF);
  valve_relay->set_component_source("gpio.switch");
  App.register_component(valve_relay);
  esp32_esp32internalgpiopin_id_3 = new esp32::ESP32InternalGPIOPin();
  esp32_esp32internalgpiopin_id_3->set_pin(::GPIO_NUM_25);
  esp32_esp32internalgpiopin_id_3->set_inverted(true);
  esp32_esp32internalgpiopin_id_3->set_drive_strength(::GPIO_DRIVE_CAP_2);
  esp32_esp32internalgpiopin_id_3->set_flags(gpio::Flags::FLAG_OUTPUT);
  valve_relay->set_pin(esp32_esp32internalgpiopin_id_3);
  // interval:
  //   - interval: 5s
  //     then:
  //       - script.execute:
  //           id: send_sensor_data
  //         type_id: script_scriptexecuteaction_id
  //     trigger_id: trigger_id_4
  //     automation_id: automation_id_5
  //     id: interval_intervaltrigger_id
  //     startup_delay: 0s
  //   - interval: 10s
  //     then:
  //       - script.execute:
  //           id: fetch_config_from_server
  //         type_id: script_scriptexecuteaction_id_2
  //     trigger_id: trigger_id_5
  //     automation_id: automation_id_6
  //     id: interval_intervaltrigger_id_2
  //     startup_delay: 0s
  interval_intervaltrigger_id = new interval::IntervalTrigger();
  interval_intervaltrigger_id->set_component_source("interval");
  App.register_component(interval_intervaltrigger_id);
  automation_id_5 = new Automation<>(interval_intervaltrigger_id);
  script_scriptexecuteaction_id = new script::ScriptExecuteAction<script::Script<>>(send_sensor_data);
  script_scriptexecuteaction_id->set_args();
  automation_id_5->add_actions({script_scriptexecuteaction_id});
  interval_intervaltrigger_id->set_update_interval(5000);
  interval_intervaltrigger_id->set_startup_delay(0);
  interval_intervaltrigger_id_2 = new interval::IntervalTrigger();
  interval_intervaltrigger_id_2->set_component_source("interval");
  App.register_component(interval_intervaltrigger_id_2);
  automation_id_6 = new Automation<>(interval_intervaltrigger_id_2);
  script_scriptexecuteaction_id_2 = new script::ScriptExecuteAction<script::Script<>>(fetch_config_from_server);
  script_scriptexecuteaction_id_2->set_args();
  automation_id_6->add_actions({script_scriptexecuteaction_id_2});
  interval_intervaltrigger_id_2->set_update_interval(10000);
  interval_intervaltrigger_id_2->set_startup_delay(0);
  // button.template:
  //   platform: template
  //   name: FORZAR LED ROJO
  //   on_press:
  //     - then:
  //         - lambda: !lambda |-
  //             auto call = id(rgb_test).turn_on();
  //             call.set_rgb(1.0, 0.0, 0.0);
  //             call.perform();
  //             ESP_LOGI("TEST", "LED FORZADO A ROJO");
  //           type_id: lambdaaction_id_3
  //       automation_id: automation_id_7
  //       trigger_id: button_buttonpresstrigger_id
  //   disabled_by_default: false
  //   id: template__templatebutton_id
  template__templatebutton_id = new template_::TemplateButton();
  App.register_button(template__templatebutton_id);
  template__templatebutton_id->set_name("FORZAR LED ROJO");
  template__templatebutton_id->set_object_id("forzar_led_rojo");
  template__templatebutton_id->set_disabled_by_default(false);
  button_buttonpresstrigger_id = new button::ButtonPressTrigger(template__templatebutton_id);
  automation_id_7 = new Automation<>(button_buttonpresstrigger_id);
  lambdaaction_id_3 = new LambdaAction<>([=]() -> void {
      #line 297 "c:\\Users\\gorra\\Desktop\\Proyecto_macetas\\riego_esp32.yaml"
      auto call = rgb_test->turn_on();
      call.set_rgb(1.0, 0.0, 0.0);
      call.perform();
      ESP_LOGI("TEST", "LED FORZADO A ROJO");
  });
  automation_id_7->add_actions({lambdaaction_id_3});
  // button.template:
  //   platform: template
  //   name: FORZAR LED AZUL
  //   on_press:
  //     - then:
  //         - lambda: !lambda |-
  //             auto call = id(rgb_test).turn_on();
  //             call.set_rgb(0.0, 0.0, 1.0);
  //             call.perform();
  //             ESP_LOGI("TEST", "LED FORZADO A AZUL");
  //           type_id: lambdaaction_id_4
  //       automation_id: automation_id_8
  //       trigger_id: button_buttonpresstrigger_id_2
  //   disabled_by_default: false
  //   id: template__templatebutton_id_2
  template__templatebutton_id_2 = new template_::TemplateButton();
  App.register_button(template__templatebutton_id_2);
  template__templatebutton_id_2->set_name("FORZAR LED AZUL");
  template__templatebutton_id_2->set_object_id("forzar_led_azul");
  template__templatebutton_id_2->set_disabled_by_default(false);
  button_buttonpresstrigger_id_2 = new button::ButtonPressTrigger(template__templatebutton_id_2);
  automation_id_8 = new Automation<>(button_buttonpresstrigger_id_2);
  lambdaaction_id_4 = new LambdaAction<>([=]() -> void {
      #line 307 "c:\\Users\\gorra\\Desktop\\Proyecto_macetas\\riego_esp32.yaml"
      auto call = rgb_test->turn_on();
      call.set_rgb(0.0, 0.0, 1.0);
      call.perform();
      ESP_LOGI("TEST", "LED FORZADO A AZUL");
  });
  automation_id_8->add_actions({lambdaaction_id_4});
  // md5:
  // socket:
  //   implementation: bsd_sockets
  // web_server_idf:
  //   {}
  http_request_httprequestsendaction_id->set_body([=]() -> std::string {
      #line 43 "c:\\Users\\gorra\\Desktop\\Proyecto_macetas\\riego_esp32.yaml"
      char json[512];
      snprintf(json, sizeof(json), 
        "{\"device_code\":\"RIEGO_001\",\"temperature\":%.2f,\"humidity\":%.2f,\"soil_voltage\":%.2f,\"rain_level\":%.2f,\"humidity_low_threshold\":%.2f,\"valve_state\":\"%s\",\"humidity_low_color\":\"%s\",\"humidity_good_color\":\"%s\"}",
        0.0,
        soil_hum->state,
        soil_raw->state,
        lluvia_test->state,
        humidity_low->state,
        (valve_relay->state ? "ON" : "OFF"),
        color_critical->state.c_str(),
        color_low->state.c_str()
      );
      return std::string(json);
  });
  http_request_httprequestsendaction_id->add_request_header("Content-Type", "application/json");
  automation_id->add_actions({http_request_httprequestsendaction_id});
  automation_id_4 = new Automation<>(fetch_config_from_server);
  http_request_httprequestsendaction_id_2 = new http_request::HttpRequestSendAction<>(http_request_httprequestidf_id);
  http_request_httprequestsendaction_id_2->set_url("https://riego-esp32-backend-production.up.railway.app/api/config/RIEGO_001");
  http_request_httprequestsendaction_id_2->set_method("GET");
  http_request_httprequestsendaction_id_2->set_capture_response(true);
  http_request_httprequestsendaction_id_2->set_max_response_buffer_size(1024);
  http_request_httprequestresponsetrigger_id = new http_request::HttpRequestResponseTrigger();
  http_request_httprequestsendaction_id_2->register_response_trigger(http_request_httprequestresponsetrigger_id);
  automation_id_2 = new Automation<std::shared_ptr<http_request::HttpContainer>, std::string &>(http_request_httprequestresponsetrigger_id);
  lambdaaction_id = new LambdaAction<std::shared_ptr<http_request::HttpContainer>, std::string &>([=](std::shared_ptr<http_request::HttpContainer> response, std::string & body) -> void {
      #line 66 "c:\\Users\\gorra\\Desktop\\Proyecto_macetas\\riego_esp32.yaml"
      std::string resp_body = body;
      ESP_LOGI("HTTP", "Body length: %d", resp_body.length());
      ESP_LOGI("RAW", "Response: %.200s", resp_body.c_str());
      
       
      float umbral = humidity_low->state;
      {
        std::string key = "\"humidity_low_threshold\"";
        size_t pos = resp_body.find(key);
        if (pos != std::string::npos) {
          size_t colon = resp_body.find(":", pos + key.length());
          if (colon != std::string::npos) {
            size_t start = colon + 1;
            while (start < resp_body.size() && isspace((unsigned char)resp_body[start])) start++;
            if (start < resp_body.size() && resp_body[start] == '"') start++;
            size_t end = start;
            while (end < resp_body.size() && (isdigit((unsigned char)resp_body[end]) || resp_body[end]=='.' || resp_body[end]=='-')) end++;
            if (end > start) {
              umbral = atof(resp_body.substr(start, end - start).c_str());
              ESP_LOGI("CONFIG", "Parsed umbral: %.1f", umbral);
            }
          }
        }
      }
      
       
      std::string color_low = "Rojo";
      std::string search_low = "\"humidity_low_color\":\"";
      size_t pos_l = resp_body.find(search_low);
      if (pos_l != std::string::npos) {
        size_t start_l = pos_l + search_low.length();
        size_t end_l = resp_body.find("\"", start_l);
        if (end_l != std::string::npos) {
          color_low = resp_body.substr(start_l, end_l - start_l);
        }
      }
      
       
      std::string color_good = "Verde";
      std::string search_good = "\"humidity_good_color\":\"";
      size_t pos_g = resp_body.find(search_good);
      if (pos_g != std::string::npos) {
        size_t start_g = pos_g + search_good.length();
        size_t end_g = resp_body.find("\"", start_g);
        if (end_g != std::string::npos) {
          color_good = resp_body.substr(start_g, end_g - start_g);
        }
      }
      
       
      float humedad_actual = soil_hum->state;
      float soil_v = soil_raw->state;
      ESP_LOGI("SENSOR", "Soil V: %.2f, Hum: %.1f, Umbral: %.1f", soil_v, humedad_actual, umbral);
      
       
      float hys = 1.0;  
      if (humedad_actual < (umbral - hys)) {
        valve_relay->turn_on();
        ESP_LOGI("VALVE", "ABRIENDO VÁLVULA: Hum %.1f < Umbral %.1f", humedad_actual, umbral);
      } else if (humedad_actual > (umbral + hys)) {
        valve_relay->turn_off();
        ESP_LOGI("VALVE", "CERRANDO VÁLVULA: Hum %.1f >= Umbral %.1f", humedad_actual, umbral);
      } else {
        ESP_LOGI("VALVE", "SIN CAMBIO: Hum %.1f Umbral %.1f", humedad_actual, umbral);
      }
  });
  automation_id_2->add_actions({lambdaaction_id});
  trigger_id_2 = new Trigger<>();
  http_request_httprequestsendaction_id_2->register_error_trigger(trigger_id_2);
  automation_id_3 = new Automation<>(trigger_id_2);
  lambdaaction_id_2 = new LambdaAction<>([=]() -> void {
      ESP_LOGD("main", "ERROR al obtener configuracion");
  });
  automation_id_3->add_actions({lambdaaction_id_2});
  automation_id_4->add_actions({http_request_httprequestsendaction_id_2});
  oled_test->set_writer([=](display::Display & it) -> void {
      #line 217 "c:\\Users\\gorra\\Desktop\\Proyecto_macetas\\riego_esp32.yaml"
       
      it.printf(0, 0, oled_font, "Humedad: %.1f%% Volt: %.2fV", soil_hum->state, soil_raw->state);
       
      it.printf(0, 16, oled_font, "Umbral: %.1f%%", humidity_low->state);
       
      if (valve_relay->state) it.printf(0, 32, oled_font, "VALVULA: ON "); else it.printf(0, 32, oled_font, "VALVULA: OFF");
       
      it.printf(0, 48, oled_font, "Lluvia V: %.2f", lluvia_test->state);
  });
  oled_test->set_i2c_bus(i2c_idfi2cbus_id);
  oled_test->set_i2c_address(0x3C);
  // =========== AUTO GENERATED CODE END ============
  App.setup();
}

void loop() {
  App.loop();
}
