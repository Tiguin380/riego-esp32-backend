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
lcd_pcf8574::PCF8574LCDDisplay *lcd_test;
dht::DHT *dht_dht_id;
esp32::ESP32InternalGPIOPin *esp32_esp32internalgpiopin_id;
sensor::Sensor *temp_test;
sensor::Sensor *hum_test;
adc::ADCSensor *lluvia_test;
sensor::MultiplyFilter *sensor_multiplyfilter_id;
esp32::ESP32InternalGPIOPin *esp32_esp32internalgpiopin_id_2;
esp32_rmt_led_strip::ESP32RMTLEDStripLightOutput *esp32_rmt_led_strip_esp32rmtledstriplightoutput_id;
light::AddressableLightState *rgb_test;
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
  App.reserve_components(22);
  // number:
  // select:
  // display:
  // sensor:
  // light:
  // button:
  // logger:
  //   id: logger_logger_id
  //   baud_rate: 115200
  //   tx_buffer_size: 512
  //   deassert_rts_dtr: false
  //   task_log_buffer_size: 768
  //   hardware_uart: UART0
  //   level: DEBUG
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
  //   id: http_request_httprequestidf_id
  //   useragent: ESPHome/2025.7.5 (https:esphome.io)
  //   follow_redirects: true
  //   redirect_limit: 3
  //   timeout: 4500ms
  //   buffer_size_rx: 512
  //   buffer_size_tx: 512
  http_request_httprequestidf_id = new http_request::HttpRequestIDF();
  http_request_httprequestidf_id->set_timeout(4500);
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
  //             rain_level\\\":%.2f,\\\"humidity_low_threshold\\\":%.2f,\\\"humidity_low_color\<cont>
  //             \":\\\"%s\\\",\\\"humidity_good_color\\\":\\\"%s\\\"}\",\n  id(temp_test).state,\n
  //             \  id(hum_test).state,\n  id(lluvia_test).state,\n  id(humidity_low).state,\n
  //             \  id(color_critical).state.c_str(),\n  id(color_low).state.c_str()\n);\n
  //             return std::string(json);"
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
  //           on_response:
  //             - then:
  //                 - lambda: !lambda |-
  //                      Parse color directamente - humidity_low_color es el color a mostrar
  //                     std::string color_led = "Verde";
  //   
  //                     size_t pos = body.find("humidity_low_color");
  //                     if (pos != std::string::npos) {
  //                       size_t start = body.find(":", pos);
  //                       start = body.find("\"", start) + 1;
  //                       size_t end = body.find("\"", start);
  //                       color_led = body.substr(start, end - start);
  //                     }
  //   
  //                     ESP_LOGI("CONFIG", "Color recibido del servidor: %s", color_led.c_str());
  //   
  //                      Convertir color a RGB
  //                     float r = 0, g = 0, b = 0;
  //                     if (color_led == "Rojo") { r = 1.0; }
  //                     else if (color_led == "Verde") { g = 1.0; }
  //                     else if (color_led == "Azul") { b = 1.0; }
  //                     else if (color_led == "Amarillo") { r = 1.0; g = 1.0; }
  //                     else if (color_led == "Cian") { g = 1.0; b = 1.0; }
  //                     else if (color_led == "Magenta") { r = 1.0; b = 1.0; }
  //                     else if (color_led == "Blanco") { r = 1.0; g = 1.0; b = 1.0; }
  //   
  //                      APLICAR COLOR DIRECTO A LOS LEDS
  //                     auto call = id(rgb_test).turn_on();
  //                     call.set_rgb(r, g, b);
  //                     call.perform();
  //   
  //                     ESP_LOGI("LED", "APLICADO: %s -> R:%.0f G:%.0f B:%.0f", color_led.c_str(), r*100, g*100, b*100);
  //                   type_id: lambdaaction_id
  //               automation_id: automation_id_2
  //               trigger_id: http_request_httprequestresponsetrigger_id
  //           on_error:
  //             - then:
  //                 - logger.log:
  //                     format: ERROR al obtener configuracion
  //                     tag: main
  //                     level: DEBUG
  //                     args: []
  //                     logger_id: logger_logger_id
  //                   type_id: lambdaaction_id_2
  //               automation_id: automation_id_3
  //               trigger_id: trigger_id_2
  //           id: http_request_httprequestidf_id
  //           capture_response: false
  //           max_response_buffer_size: 1000
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
  //   min_value: 30.0
  //   max_value: 80.0
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
  humidity_low->traits.set_min_value(30.0f);
  humidity_low->traits.set_max_value(80.0f);
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
  // display.lcd_pcf8574:
  //   platform: lcd_pcf8574
  //   id: lcd_test
  //   dimensions:
  //     - 16
  //     - 2
  //   address: 0x27
  //   lambda: !lambda |-
  //     it.printf(0, 0, "Temp: %.1fC", id(temp_test).state);
  //     it.printf(0, 1, "Hum: %.1f%%", id(hum_test).state);
  //   update_interval: 1s
  //   i2c_id: i2c_idfi2cbus_id
  lcd_test = new lcd_pcf8574::PCF8574LCDDisplay();
  lcd_test->set_update_interval(1000);
  lcd_test->set_component_source("display");
  App.register_component(lcd_test);
  lcd_test->set_dimensions(16, 2);
  lcd_test->set_i2c_bus(i2c_idfi2cbus_id);
  lcd_test->set_i2c_address(0x27);
  // sensor.dht:
  //   platform: dht
  //   model: DHT11
  //   pin:
  //     number: 17
  //     mode:
  //       input: true
  //       pullup: true
  //       output: false
  //       open_drain: false
  //       pulldown: false
  //     id: esp32_esp32internalgpiopin_id
  //     inverted: false
  //     ignore_pin_validation_error: false
  //     ignore_strapping_warning: false
  //     drive_strength: 20.0
  //   update_interval: 5s
  //   temperature:
  //     name: Temp Test
  //     id: temp_test
  //     disabled_by_default: false
  //     force_update: false
  //     unit_of_measurement: °C
  //     accuracy_decimals: 1
  //     device_class: temperature
  //     state_class: measurement
  //   humidity:
  //     name: Hum Test
  //     id: hum_test
  //     disabled_by_default: false
  //     force_update: false
  //     unit_of_measurement: '%'
  //     accuracy_decimals: 0
  //     device_class: humidity
  //     state_class: measurement
  //   id: dht_dht_id
  dht_dht_id = new dht::DHT();
  dht_dht_id->set_update_interval(5000);
  dht_dht_id->set_component_source("dht.sensor");
  App.register_component(dht_dht_id);
  esp32_esp32internalgpiopin_id = new esp32::ESP32InternalGPIOPin();
  esp32_esp32internalgpiopin_id->set_pin(::GPIO_NUM_17);
  esp32_esp32internalgpiopin_id->set_inverted(false);
  esp32_esp32internalgpiopin_id->set_drive_strength(::GPIO_DRIVE_CAP_2);
  esp32_esp32internalgpiopin_id->set_flags((gpio::Flags::FLAG_INPUT | gpio::Flags::FLAG_PULLUP));
  dht_dht_id->set_pin(esp32_esp32internalgpiopin_id);
  temp_test = new sensor::Sensor();
  App.register_sensor(temp_test);
  temp_test->set_name("Temp Test");
  temp_test->set_object_id("temp_test");
  temp_test->set_disabled_by_default(false);
  temp_test->set_device_class("temperature");
  temp_test->set_state_class(sensor::STATE_CLASS_MEASUREMENT);
  temp_test->set_unit_of_measurement("\302\260C");
  temp_test->set_accuracy_decimals(1);
  temp_test->set_force_update(false);
  dht_dht_id->set_temperature_sensor(temp_test);
  hum_test = new sensor::Sensor();
  App.register_sensor(hum_test);
  hum_test->set_name("Hum Test");
  hum_test->set_object_id("hum_test");
  hum_test->set_disabled_by_default(false);
  hum_test->set_device_class("humidity");
  hum_test->set_state_class(sensor::STATE_CLASS_MEASUREMENT);
  hum_test->set_unit_of_measurement("%");
  hum_test->set_accuracy_decimals(0);
  hum_test->set_force_update(false);
  dht_dht_id->set_humidity_sensor(hum_test);
  dht_dht_id->set_dht_model(dht::DHT_MODEL_DHT11);
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
  sensor_multiplyfilter_id = new sensor::MultiplyFilter(3.3f);
  lluvia_test->set_filters({sensor_multiplyfilter_id});
  esp32_esp32internalgpiopin_id_2 = new esp32::ESP32InternalGPIOPin();
  esp32_esp32internalgpiopin_id_2->set_pin(::GPIO_NUM_34);
  esp32_esp32internalgpiopin_id_2->set_inverted(false);
  esp32_esp32internalgpiopin_id_2->set_drive_strength(::GPIO_DRIVE_CAP_2);
  esp32_esp32internalgpiopin_id_2->set_flags(gpio::Flags::FLAG_INPUT);
  lluvia_test->set_pin(esp32_esp32internalgpiopin_id_2);
  lluvia_test->set_output_raw(false);
  lluvia_test->set_sample_count(1);
  lluvia_test->set_sampling_mode(adc::SamplingMode::AVG);
  lluvia_test->set_attenuation(ADC_ATTEN_DB_0);
  lluvia_test->set_channel1(::ADC1_CHANNEL_6);
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
      #line 222 "riego_esp32.yaml"
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
      #line 232 "riego_esp32.yaml"
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
      #line 41 "riego_esp32.yaml"
      char json[512];
      snprintf(json, sizeof(json), 
        "{\"device_code\":\"RIEGO_001\",\"temperature\":%.2f,\"humidity\":%.2f,\"rain_level\":%.2f,\"humidity_low_threshold\":%.2f,\"humidity_low_color\":\"%s\",\"humidity_good_color\":\"%s\"}",
        temp_test->state,
        hum_test->state,
        lluvia_test->state,
        humidity_low->state,
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
  http_request_httprequestsendaction_id_2->set_capture_response(false);
  http_request_httprequestsendaction_id_2->set_max_response_buffer_size(1000);
  http_request_httprequestresponsetrigger_id = new http_request::HttpRequestResponseTrigger();
  http_request_httprequestsendaction_id_2->register_response_trigger(http_request_httprequestresponsetrigger_id);
  automation_id_2 = new Automation<std::shared_ptr<http_request::HttpContainer>, std::string &>(http_request_httprequestresponsetrigger_id);
  lambdaaction_id = new LambdaAction<std::shared_ptr<http_request::HttpContainer>, std::string &>([=](std::shared_ptr<http_request::HttpContainer> response, std::string & body) -> void {
      #line 60 "riego_esp32.yaml"
       
      std::string color_led = "Verde";
      
      size_t pos = body.find("humidity_low_color");
      if (pos != std::string::npos) {
        size_t start = body.find(":", pos);
        start = body.find("\"", start) + 1;
        size_t end = body.find("\"", start);
        color_led = body.substr(start, end - start);
      }
      
      ESP_LOGI("CONFIG", "Color recibido del servidor: %s", color_led.c_str());
      
       
      float r = 0, g = 0, b = 0;
      if (color_led == "Rojo") { r = 1.0; }
      else if (color_led == "Verde") { g = 1.0; }
      else if (color_led == "Azul") { b = 1.0; }
      else if (color_led == "Amarillo") { r = 1.0; g = 1.0; }
      else if (color_led == "Cian") { g = 1.0; b = 1.0; }
      else if (color_led == "Magenta") { r = 1.0; b = 1.0; }
      else if (color_led == "Blanco") { r = 1.0; g = 1.0; b = 1.0; }
      
       
      auto call = rgb_test->turn_on();
      call.set_rgb(r, g, b);
      call.perform();
      
      ESP_LOGI("LED", "APLICADO: %s -> R:%.0f G:%.0f B:%.0f", color_led.c_str(), r*100, g*100, b*100);
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
  lcd_test->set_writer([=](lcd_pcf8574::PCF8574LCDDisplay & it) -> void {
      #line 170 "riego_esp32.yaml"
      it.printf(0, 0, "Temp: %.1fC", temp_test->state);
      it.printf(0, 1, "Hum: %.1f%%", hum_test->state);
  });
  // =========== AUTO GENERATED CODE END ============
  App.setup();
}

void loop() {
  App.loop();
}
