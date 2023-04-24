/* CoAP server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
 * WARNING
 * libcoap is not multi-thread safe, so only this thread must make any coap_*()
 * calls.  Any external (to this thread) data transmitted in/out via libcoap
 * therefore has to be passed in/out by xQueue*() via this thread.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "nvs_flash.h"

#include "protocol_examples_common.h"

#include "coap3/coap.h"

#include "driver/gpio.h"
#include "freertos/queue.h"

#include "mdns.h"
#ifndef CONFIG_COAP_SERVER_SUPPORT
#error COAP_SERVER_SUPPORT needs to be enabled
#endif /* COAP_SERVER_SUPPORT */

/* The examples use simple Pre-Shared-Key configuration that you can set via
   'idf.py menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_COAP_PSK_KEY "some-agreed-preshared-key"

   Note: PSK will only be used if the URI is prefixed with coaps://
   instead of coap:// and the PSK must be one that the server supports
   (potentially associated with the IDENTITY)
*/
#define EXAMPLE_COAP_PSK_KEY CONFIG_EXAMPLE_COAP_PSK_KEY

/* The examples use CoAP Logging Level that
   you can set via 'idf.py menuconfig'.

   If you'd rather not, just change the below entry to a value
   that is between 0 and 7 with
   the config you want - ie #define EXAMPLE_COAP_LOG_DEFAULT_LEVEL 7
*/
#define EXAMPLE_COAP_LOG_DEFAULT_LEVEL CONFIG_COAP_LOG_DEFAULT_LEVEL

const static char *TAG = "CoAP_server";
const static char *ISR = "I/O isr";

static char espressif_data[100];
static int espressif_data_len = 0;


#ifdef CONFIG_COAP_MBEDTLS_PKI
/* CA cert, taken from coap_ca.pem
   Server cert, taken from coap_server.crt
   Server key, taken from coap_server.key

   The PEM, CRT and KEY file are examples taken from
   https://github.com/eclipse/californium/tree/master/demo-certs/src/main/resources
   as the Certificate test (by default) for the coap_client is against the
   californium server.

   To embed it in the app binary, the PEM, CRT and KEY file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
 */
extern uint8_t ca_pem_start[] asm("_binary_coap_ca_pem_start");
extern uint8_t ca_pem_end[]   asm("_binary_coap_ca_pem_end");
extern uint8_t server_crt_start[] asm("_binary_coap_server_crt_start");
extern uint8_t server_crt_end[]   asm("_binary_coap_server_crt_end");
extern uint8_t server_key_start[] asm("_binary_coap_server_key_start");
extern uint8_t server_key_end[]   asm("_binary_coap_server_key_end");
#endif /* CONFIG_COAP_MBEDTLS_PKI */

#define GPIO_OUTPUT_IO_RUN      13  
#define GPIO_OUTPUT_IO_ALARM    15
#define GPIO_OUTPUT_PIN_SEL  ((1ULL<<GPIO_OUTPUT_IO_ALARM) | (1ULL<<GPIO_OUTPUT_IO_RUN))
#define GPIO_INPUT_IO_ALARM     33 
#define GPIO_INPUT_IO_RUN    35 //35 ->B2
#define GPIO_INPUT_PIN_SEL  ((1ULL<<GPIO_INPUT_IO_ALARM) | (1ULL<<GPIO_INPUT_IO_RUN))
#define ESP_INTR_FLAG_DEFAULT 0


#define INITIAL_DATA "Hello World!"

static uint8_t alarm_flag = 0;
static uint8_t run_flag = 0;
static int adc_values[10] = { 12, 13, 14, 13, 12, 12, 13, 15, 16, 13};
static uint8_t adc_count = 0;

static QueueHandle_t gpio_evt_queue = NULL;

// static void blink_led(void)
// {
//     /* Set the GPIO level according to the state (LOW or HIGH)*/
//     gpio_set_level(14, s_led_state);
// }

static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    uint32_t gpio_num = (uint32_t) arg;
    xQueueSendFromISR(gpio_evt_queue, &gpio_num, NULL);
}

static void gpio_task_inputs(void* arg)
{
    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
           // printf("GPIO[%"PRIu32"] intr, val: %d\n", io_num, gpio_get_level(io_num));
            if(io_num == GPIO_INPUT_IO_ALARM){
               // printf ("entro if GPIO_INPUT_IO_0");
                alarm_flag  = 1;
                run_flag = 0;
                gpio_set_level(GPIO_OUTPUT_IO_ALARM, alarm_flag);
                gpio_set_level(GPIO_OUTPUT_IO_RUN, run_flag);
                ESP_LOGI(ISR,"I/O ALARM push button");
            }else if(io_num == GPIO_INPUT_IO_RUN){
                //printf ("entro if GPIO_INPUT_IO_0");
                alarm_flag  = 0;
                run_flag = 1;
                gpio_set_level(GPIO_OUTPUT_IO_ALARM, alarm_flag);
                gpio_set_level(GPIO_OUTPUT_IO_RUN, run_flag);
                ESP_LOGI(ISR,"I/O RUN push button");
            }
        }
    }
}

static void configure_IO(void)
{
    //zero-initialize the config structure.
    gpio_config_t io_conf = {};
    //disable interrupt
    io_conf.intr_type = GPIO_INTR_DISABLE;
    //set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    //bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;
    //disable pull-down mode
    io_conf.pull_down_en = 0;
    //disable pull-up mode
    io_conf.pull_up_en = 0;
    //configure GPIO with the given settings
    gpio_config(&io_conf);

    //interrupt of rising edge
    io_conf.intr_type = GPIO_INTR_POSEDGE;
    //bit mask of the pins, use GPIO4/5 here
    io_conf.pin_bit_mask = GPIO_INPUT_PIN_SEL;
    //set as input mode
    io_conf.mode = GPIO_MODE_INPUT;
    //enable pull-up mode
    io_conf.pull_up_en = 1;
    gpio_config(&io_conf);

    //create a queue to handle gpio event from isr
    gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t));
    //start gpio task
    xTaskCreate(gpio_task_inputs, "gpio_task_inputs", 2048, NULL, 10, NULL);

    //install gpio isr service
    gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
    //hook isr handler for specific gpio pin
    gpio_isr_handler_add(GPIO_INPUT_IO_ALARM, gpio_isr_handler, (void*) GPIO_INPUT_IO_ALARM);
    //hook isr handler for specific gpio pin
    gpio_isr_handler_add(GPIO_INPUT_IO_RUN, gpio_isr_handler, (void*) GPIO_INPUT_IO_RUN);

}

/*
 * Alarm resource handler
 */
static void
hnd_alarm_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{

    ESP_LOGI(TAG, " hnd_alarm_get executed");  
    gpio_set_level(14, alarm_flag);
    if(alarm_flag == 1){
        sprintf(espressif_data,"Generador en Alarma");
        espressif_data_len = strlen(espressif_data);
    }
    else{
        sprintf(espressif_data,"Generador OK - No Alarmas");
        espressif_data_len = strlen(espressif_data);
    }
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)espressif_data_len,
                                 (const u_char *)espressif_data,
                                 NULL, NULL);
}

/*
 * Status (Merged with Coontrol) resource handler
 */
static void
hnd_status_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    ESP_LOGI(TAG, " hnd_status_get executed");
    if(run_flag == 1){
        sprintf(espressif_data,"Generador Encendido");
        espressif_data_len = strlen(espressif_data);
    }
    else{
        sprintf(espressif_data,"Generador Apagado");
        espressif_data_len = strlen(espressif_data);
    }
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)espressif_data_len,
                                 (const u_char *)espressif_data,
                                 NULL, NULL);
}

static void
hnd_status_put(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
                  {
    
    size_t size;
    size_t offset;
    size_t total;
    const unsigned char *data;

    coap_resource_notify_observers(resource, NULL);

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
   // printf("entro hnd_status_put");
    ESP_LOGI(TAG, " hnd_status_put executed");

    /* coap_get_data_large() sets size to 0 on error */
    (void)coap_get_data_large(request, &size, &data, &offset, &total);

    if (size == 0) {      /* re-init */
        run_flag = 0;
        printf("hnd_status_put size =0");
        ESP_LOGI(TAG, "hnd_status_put size =0");

    } else {
        // espressif_data_len = size > sizeof (espressif_data) ? sizeof (espressif_data) : size;
        // memcpy (espressif_data, data, espressif_data_len);
        if ('a' == (int)*data) {
            run_flag = 0;
            printf("hnd_status_put apagar\n");
            ESP_LOGI(TAG, "hnd_status_put Apagar Generador");
           gpio_set_level(GPIO_OUTPUT_IO_RUN, run_flag);     
        }
        else if ('e' == (int)*data) {
            run_flag = 1;
            printf("hnd_status_put encender\n");
            ESP_LOGI(TAG, "hnd_status_put Encender Generador");
            gpio_set_level(GPIO_OUTPUT_IO_RUN, run_flag);
        }
        else{
            printf("Payload not compatible\n");
            ESP_LOGE(TAG, "Payload not compatible, %d", size);  
        }
    }
}

/*
 * Reset resource handler
 */
static void
hnd_reset_put(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    size_t size;
    size_t offset;
    size_t total;
    const unsigned char *data;
    ESP_LOGI(TAG, " hnd_reset_put executed");

    coap_resource_notify_observers(resource, NULL);

    // if (strcmp (espressif_data, INITIAL_DATA) == 0) {
    //     coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    // } else {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    // }

    /* coap_get_data_large() sets size to 0 on error */
    (void)coap_get_data_large(request, &size, &data, &offset, &total);
    alarm_flag = 0 ;
    run_flag = 0;
    gpio_set_level(GPIO_OUTPUT_IO_ALARM, alarm_flag);
    gpio_set_level(GPIO_OUTPUT_IO_RUN, run_flag);

    // if (size == 0) {      /* re-init */
    //     snprintf(espressif_data, sizeof(espressif_data), INITIAL_DATA);
    //     espressif_data_len = strlen(espressif_data);
    // } else {
    //     espressif_data_len = size > sizeof (espressif_data) ? sizeof (espressif_data) : size;
    //     memcpy (espressif_data, data, espressif_data_len);
    // }
}

/*
 * Battery resource handler
 */
static void
hnd_battery_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    sprintf(espressif_data, "Battery voltage = %d", adc_values[adc_count]);
    adc_count++;
    if (adc_count >9){
        adc_count = 0;
    }
    //espressif_data_len = sizeof("Battery voltage = ")+2;
    espressif_data_len = strlen(espressif_data);

    ESP_LOGI(TAG, " hnd_battery_get executed");

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)espressif_data_len,
                                 (const u_char *)espressif_data,
                                 NULL, NULL);
}


// static void
// hnd_espressif_delete(coap_resource_t *resource,
//                      coap_session_t *session,
//                      const coap_pdu_t *request,
//                      const coap_string_t *query,
//                      coap_pdu_t *response)
// {
//     coap_resource_notify_observers(resource, NULL);
//     snprintf(espressif_data, sizeof(espressif_data), INITIAL_DATA);
//     espressif_data_len = strlen(espressif_data);
//     coap_pdu_set_code(response, COAP_RESPONSE_CODE_DELETED);
// }

#ifdef CONFIG_COAP_MBEDTLS_PKI

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert,
                   size_t asn1_length,
                   coap_session_t *session,
                   unsigned depth,
                   int validated,
                   void *arg
                  )
{
    coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
             cn, depth ? "CA" : "Certificate");
    return 1;
}
#endif /* CONFIG_COAP_MBEDTLS_PKI */

static void
coap_log_handler (coap_log_t level, const char *message)
{
    uint32_t esp_level = ESP_LOG_INFO;
    char *cp = strchr(message, '\n');

    if (cp)
        ESP_LOG_LEVEL(esp_level, TAG, "%.*s", (int)(cp-message), message);
    else
        ESP_LOG_LEVEL(esp_level, TAG, "%s", message);
}

static void coap_example_server(void *p)
{
    coap_context_t *ctx = NULL;
    coap_address_t serv_addr;
    coap_resource_t *resource_alarm = NULL;
    coap_resource_t *resource_control = NULL;
    coap_resource_t *resource_reset = NULL;
    coap_resource_t *resource_battery = NULL;

    /***********************************
    * If adding mDNS it goes here.
    ***********************************/
     mdns_init();
     mdns_hostname_set("DorianESP32");

     mdns_txt_item_t serviceTxtData[3] = {
         {"board", "esp32"},
         {"user", "user"},
         {"password","password"}
     };
     mdns_service_add("DorianESP32", "_coap","_udp",80, serviceTxtData, 3);
     //mdns_service_add("DORIAN-ESP32", "_coap","_udp",5683, serviceTxtData, 3);

    snprintf(espressif_data, sizeof(espressif_data), INITIAL_DATA);
    espressif_data_len = strlen(espressif_data);
    coap_set_log_handler(coap_log_handler);
    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);

    while (1) {
        coap_endpoint_t *ep = NULL;
        unsigned wait_ms;
        int have_dtls = 0;

        /* Prepare the CoAP server socket */
        coap_address_init(&serv_addr);
        serv_addr.addr.sin6.sin6_family = AF_INET6;
        serv_addr.addr.sin6.sin6_port   = htons(COAP_DEFAULT_PORT);

        ctx = coap_new_context(NULL);
        if (!ctx) {
            ESP_LOGE(TAG, "coap_new_context() failed");
            continue;
        }
        coap_context_set_block_mode(ctx,
                                    COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);
#ifdef CONFIG_COAP_MBEDTLS_PSK
        /* Need PSK setup before we set up endpoints */
        coap_context_set_psk(ctx, "CoAP",
                             (const uint8_t *)EXAMPLE_COAP_PSK_KEY,
                             sizeof(EXAMPLE_COAP_PSK_KEY) - 1);
#endif /* CONFIG_COAP_MBEDTLS_PSK */

#ifdef CONFIG_COAP_MBEDTLS_PKI
        /* Need PKI setup before we set up endpoints */
        unsigned int ca_pem_bytes = ca_pem_end - ca_pem_start;
        unsigned int server_crt_bytes = server_crt_end - server_crt_start;
        unsigned int server_key_bytes = server_key_end - server_key_start;
        coap_dtls_pki_t dtls_pki;

        memset (&dtls_pki, 0, sizeof(dtls_pki));
        dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
        if (ca_pem_bytes) {
            /*
             * Add in additional certificate checking.
             * This list of enabled can be tuned for the specific
             * requirements - see 'man coap_encryption'.
             *
             * Note: A list of root ca file can be setup separately using
             * coap_context_set_pki_root_cas(), but the below is used to
             * define what checking actually takes place.
             */
            dtls_pki.verify_peer_cert        = 1;
            dtls_pki.check_common_ca         = 1;
            dtls_pki.allow_self_signed       = 1;
            dtls_pki.allow_expired_certs     = 1;
            dtls_pki.cert_chain_validation   = 1;
            dtls_pki.cert_chain_verify_depth = 2;
            dtls_pki.check_cert_revocation   = 1;
            dtls_pki.allow_no_crl            = 1;
            dtls_pki.allow_expired_crl       = 1;
            dtls_pki.allow_bad_md_hash       = 1;
            dtls_pki.allow_short_rsa_length  = 1;
            dtls_pki.validate_cn_call_back   = verify_cn_callback;
            dtls_pki.cn_call_back_arg        = NULL;
            dtls_pki.validate_sni_call_back  = NULL;
            dtls_pki.sni_call_back_arg       = NULL;
        }
        dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
        dtls_pki.pki_key.key.pem_buf.public_cert = server_crt_start;
        dtls_pki.pki_key.key.pem_buf.public_cert_len = server_crt_bytes;
        dtls_pki.pki_key.key.pem_buf.private_key = server_key_start;
        dtls_pki.pki_key.key.pem_buf.private_key_len = server_key_bytes;
        dtls_pki.pki_key.key.pem_buf.ca_cert = ca_pem_start;
        dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_pem_bytes;

        coap_context_set_pki(ctx, &dtls_pki);
#endif /* CONFIG_COAP_MBEDTLS_PKI */

        ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
        if (!ep) {
            ESP_LOGE(TAG, "udp: coap_new_endpoint() failed");
            goto clean_up;
        }
        if (coap_tcp_is_supported()) {
            ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_TCP);
            if (!ep) {
                ESP_LOGE(TAG, "tcp: coap_new_endpoint() failed");
                goto clean_up;
            }
        }
#if defined(CONFIG_COAP_MBEDTLS_PSK) || defined(CONFIG_COAP_MBEDTLS_PKI)
        if (coap_dtls_is_supported()) {
#ifndef CONFIG_MBEDTLS_TLS_SERVER
            /* This is not critical as unencrypted support is still available */
            ESP_LOGI(TAG, "MbedTLS DTLS Server Mode not configured");
#else /* CONFIG_MBEDTLS_TLS_SERVER */
            serv_addr.addr.sin6.sin6_port = htons(COAPS_DEFAULT_PORT);
            ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_DTLS);
            if (!ep) {
                ESP_LOGE(TAG, "dtls: coap_new_endpoint() failed");
                goto clean_up;
            }
            have_dtls = 1;
#endif /* CONFIG_MBEDTLS_TLS_SERVER */
        }
        if (coap_tls_is_supported()) {
#ifndef CONFIG_MBEDTLS_TLS_SERVER
            /* This is not critical as unencrypted support is still available */
            ESP_LOGI(TAG, "MbedTLS TLS Server Mode not configured");
#else /* CONFIG_MBEDTLS_TLS_SERVER */
            serv_addr.addr.sin6.sin6_port = htons(COAPS_DEFAULT_PORT);
            ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_TLS);
            if (!ep) {
                ESP_LOGE(TAG, "tls: coap_new_endpoint() failed");
                goto clean_up;
            }
#endif /* CONFIG_MBEDTLS_TLS_SERVER */
        }
        if (!have_dtls) {
            /* This is not critical as unencrypted support is still available */
            ESP_LOGI(TAG, "MbedTLS (D)TLS Server Mode not configured");
        }
#endif /* CONFIG_COAP_MBEDTLS_PSK || CONFIG_COAP_MBEDTLS_PKI */
        
/*
*Resource Handlers
*
**/
       // Common alarm
        /* Here you initialize the resource */
        resource_alarm = coap_resource_init(coap_make_str_const("Alarm/status"), 0);
        if (!resource_alarm) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        /* Here is were you register each resource handler (GET,PUT and DELETE) */
        coap_register_handler(resource_alarm, COAP_REQUEST_GET, hnd_alarm_get);
        //coap_register_handler(resource_alarm, COAP_REQUEST_PUT, hnd_alarm_put);
        //coap_register_handler(resource_alarm, COAP_REQUEST_DELETE, hnd_alarm_delete);
        /* We possibly want to Observe the GETs */
        coap_resource_set_get_observable(resource_alarm, 1);
        coap_add_resource(ctx, resource_alarm);

       // Control (merged with status) - Gen running or not
        /* Here you initialize the resource */
        resource_control = coap_resource_init(coap_make_str_const("Status"), 0);
        if (!resource_control) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        /* Here is were you register each resource handler (GET,PUT and DELETE) */
        coap_register_handler(resource_control, COAP_REQUEST_GET, hnd_status_get);
        coap_register_handler(resource_control, COAP_REQUEST_PUT, hnd_status_put);
        //coap_register_handler(resource_status, COAP_REQUEST_DELETE, hnd_status_delete);
        /* We possibly want to Observe the GETs */
        coap_resource_set_get_observable(resource_control, 1);
        coap_add_resource(ctx, resource_control);
       
       // Alarm Reset
        /* Here you initialize the resource */
        resource_reset = coap_resource_init(coap_make_str_const("Alarm/Reset"), 0);
        if (!resource_reset) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        /* Here is were you register each resource handler (GET,PUT and DELETE) */
        //coap_register_handler(resource_reset, COAP_REQUEST_GET, hnd_espressif_get);
        coap_register_handler(resource_reset, COAP_REQUEST_PUT, hnd_reset_put);
        // coap_register_handler(resource_reset, COAP_REQUEST_DELETE, hnd_espressif_delete);
        /* We possibly want to Observe the GETs */
        coap_resource_set_get_observable(resource_reset, 1);
        coap_add_resource(ctx, resource_reset);


       //Battery Voltage
        /* Here you initialize the resource */
        resource_battery = coap_resource_init(coap_make_str_const("Battery"), 0);
        if (!resource_battery) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        /* Here is were you register each resource handler (GET,PUT and DELETE) */
        coap_register_handler(resource_battery, COAP_REQUEST_GET, hnd_battery_get);
        /* We possibly want to Observe the GETs */
        coap_resource_set_get_observable(resource_battery, 1);
        coap_add_resource(ctx, resource_battery);





#if defined(CONFIG_EXAMPLE_COAP_MCAST_IPV4) || defined(CONFIG_EXAMPLE_COAP_MCAST_IPV6)
        esp_netif_t *netif = NULL;
        for (int i = 0; i < esp_netif_get_nr_of_ifs(); ++i) {
            char buf[8];
            netif = esp_netif_next(netif);
            esp_netif_get_netif_impl_name(netif, buf);
#if defined(CONFIG_EXAMPLE_COAP_MCAST_IPV4)
            coap_join_mcast_group_intf(ctx, CONFIG_EXAMPLE_COAP_MULTICAST_IPV4_ADDR, buf);
#endif /* CONFIG_EXAMPLE_COAP_MCAST_IPV4 */
#if defined(CONFIG_EXAMPLE_COAP_MCAST_IPV6)
            /* When adding IPV6 esp-idf requires ifname param to be filled in */
            coap_join_mcast_group_intf(ctx, CONFIG_EXAMPLE_COAP_MULTICAST_IPV6_ADDR, buf);
#endif /* CONFIG_EXAMPLE_COAP_MCAST_IPV6 */
        }
#endif /* CONFIG_EXAMPLE_COAP_MCAST_IPV4 || CONFIG_EXAMPLE_COAP_MCAST_IPV6 */

        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

        while (1) {
            int result = coap_io_process(ctx, wait_ms);
            if (result < 0) {
                break;
            } else if (result && (unsigned)result < wait_ms) {
                /* decrement if there is a result wait time returned */
                wait_ms -= result;
            }
            if (result) {
                /* result must have been >= wait_ms, so reset wait_ms */
                wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
            }
        }
    }
clean_up:
    coap_free_context(ctx);
    coap_cleanup();

    vTaskDelete(NULL);
}

void app_main(void)
{
    configure_IO();
    ESP_ERROR_CHECK( nvs_flash_init() );
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
    xTaskCreate(coap_example_server, "coap", 8 * 1024, NULL, 5, NULL);
}
