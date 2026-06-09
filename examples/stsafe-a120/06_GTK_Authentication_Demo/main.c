/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 GTK3 Authentication Demo — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Build requirements: pkg-config gtk+-3.0, libstse.so, -lpthread
 * Usage:  ./06_GTK_Authentication_Demo [busID]   (default busID = 1)
 ******************************************************************************
 */

#include "Apps_utils.h"
#include <gtk/gtk.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ST STSAFE-A Production CA 01 — self-signed root certificate (SPL02/03/05) */
#define CA_SELF_SIGNED_CERTIFICATE_01                                                    \
        0x30, 0x82, 0x01, 0xA0, 0x30, 0x82, 0x01, 0x46, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, \
        0x01, 0x01,     \
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x4F, 0x31, 0x0B, \
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4C, 0x31, 0x1E, 0x30, 0x1C, 0x06, \
        0x03, 0x55, 0x04, 0x0A, 0x0C, 0x15, 0x53, 0x54, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x65, 0x6C, 0x65, \
        0x63, 0x74, 0x72, 0x6F, 0x6E, 0x69, 0x63, 0x73, 0x20, 0x6E, 0x76, 0x31, 0x20, 0x30, 0x1E, 0x06, \
        0x03, 0x55, 0x04, 0x03, 0x0C, 0x17, 0x53, 0x54, 0x4D, 0x20, 0x53, 0x54, 0x53, 0x41, 0x46, 0x45, \
        0x2D, 0x41, 0x20, 0x50, 0x52, 0x4F, 0x44, 0x20, 0x43, 0x41, 0x20, 0x30, 0x31, 0x30, 0x1E, 0x17, \
        0x0D, 0x31, 0x38, 0x30, 0x37, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, \
        0x34, 0x38, 0x30, 0x37, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x4F, 0x31, \
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4C, 0x31, 0x1E, 0x30, 0x1C, \
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x15, 0x53, 0x54, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x65, 0x6C, \
        0x65, 0x63, 0x74, 0x72, 0x6F, 0x6E, 0x69, 0x63, 0x73, 0x20, 0x6E, 0x76, 0x31, 0x20, 0x30, 0x1E, \
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x17, 0x53, 0x54, 0x4D, 0x20, 0x53, 0x54, 0x53, 0x41, 0x46, \
        0x45, 0x2D, 0x41, 0x20, 0x50, 0x52, 0x4F, 0x44, 0x20, 0x43, 0x41, 0x20, 0x30, 0x31, 0x30, 0x59, \
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, \
        0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x82, 0x19, 0x4F, 0x26, 0xCC, 0xA3, 0x6E, \
        0x0E, 0x82, 0x19, 0x5C, 0xE6, 0x66, 0x58, 0xEC, 0x64, 0xA4, 0x66, 0x92, 0x2F, 0x58, 0xC9, 0xE6, \
        0x4B, 0x5D, 0xE1, 0xA2, 0x9E, 0x7F, 0x39, 0x86, 0x3D, 0x04, 0x26, 0x92, 0xE4, 0xC8, 0xAC, 0x79, \
        0xF9, 0x6D, 0x2F, 0xED, 0x52, 0x77, 0x4D, 0x52, 0x81, 0x95, 0x39, 0xF2, 0x1F, 0x3E, 0xCD, 0x19, \
        0x38, 0xF8, 0x3D, 0x70, 0xAE, 0xE0, 0x9C, 0xCD, 0x8D, 0xA3, 0x13, 0x30, 0x11, 0x30, 0x0F, 0x06, \
        0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, \
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, \
        0x20, 0x6E, 0xE5, 0x43, 0x32, 0x47, 0xAC, 0x72, 0x34, 0xFC, 0x9D, 0x17, 0x5A, 0xA5, 0x1E, 0x83, \
        0x27, 0x69, 0x01, 0xAD, 0xEC, 0x1F, 0x00, 0x5E, 0x37, 0x1F, 0x40, 0x73, 0x4D, 0xE3, 0x8C, 0xC5, \
        0x2E, 0x02, 0x21, 0x00, 0xB1, 0xD9, 0x51, 0x6A, 0xAD, 0x9A, 0x3E, 0x86, 0xD2, 0x2B, 0x8E, 0x3B, \
        0x3B, 0xD0, 0x14, 0x6F, 0xAB, 0xB9, 0xB9, 0x22, 0xF0, 0x45, 0x26, 0x34, 0xFE, 0x92, 0x7F, 0xF5, \
        0xD6, 0x36, 0xCD, 0x90

#define STSAFE_CERTIFICATE_ZONE_0      0U
#define STSE_STATIC_PRIVATE_KEY_SLOT_0 0U
#define DEFAULT_I2C_BUS_ID             1U
#define RESULT_TEXT_MAX_LEN            16384

typedef struct {
    GtkWidget      *window;
    GtkWidget      *btn_authenticate;
    GtkWidget      *lbl_status;
    GtkWidget      *txt_results;
    GtkWidget      *spin_bus;
    GtkWidget      *spinner;
    stse_Handler_t  stse_handler;
    int             bus_id;
    GMutex          result_mutex;
    gboolean        auth_success;
    char            result_text[RESULT_TEXT_MAX_LEN];
} AppState;

/* -----------------------------------------------------------------------
 * Worker thread: performs authentication + data storage query off the
 * GTK main loop to keep the UI responsive.
 * ---------------------------------------------------------------------- */
static gboolean update_ui_idle(gpointer user_data)
{
    AppState *app = (AppState *)user_data;

    g_mutex_lock(&app->result_mutex);

    gtk_spinner_stop(GTK_SPINNER(app->spinner));
    gtk_widget_set_sensitive(app->btn_authenticate, TRUE);

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->txt_results));
    gtk_text_buffer_set_text(buf, app->result_text, -1);

    if (app->auth_success) {
        gtk_label_set_markup(GTK_LABEL(app->lbl_status),
                             "<span foreground='green' font_weight='bold'>"
                             "Authentication: PASS</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(app->lbl_status),
                             "<span foreground='red' font_weight='bold'>"
                             "Authentication: FAIL</span>");
    }

    g_mutex_unlock(&app->result_mutex);
    return G_SOURCE_REMOVE;
}

static void *auth_worker_thread(void *arg)
{
    AppState       *app = (AppState *)arg;
    stse_ReturnCode_t stse_ret;
    char            *p = app->result_text;
    size_t           rem = sizeof(app->result_text);

    static const uint8_t ca_selfsigned_cert[] = {CA_SELF_SIGNED_CERTIFICATE_01};

    g_mutex_lock(&app->result_mutex);
    app->auth_success = FALSE;
    g_mutex_unlock(&app->result_mutex);

#define APPEND(...) do { int _n = snprintf(p, rem, __VA_ARGS__); if (_n > 0) { p += _n; rem -= (size_t)_n; } } while (0)

    APPEND("I2C bus: /dev/i2c-%d\n\n", app->bus_id);

    /* Initialize STSAFE-A handler */
    stse_ret = stse_set_default_handler_value(&app->stse_handler);
    if (stse_ret != STSE_OK) {
        APPEND("stse_set_default_handler_value error: 0x%04X\n", stse_ret);
        g_idle_add(update_ui_idle, app);
        return NULL;
    }

    app->stse_handler.device_type  = STSAFE_A120;
    app->stse_handler.io.busID     = (uint8_t)app->bus_id;
    app->stse_handler.io.BusSpeed  = 400;

    stse_ret = stse_init(&app->stse_handler);
    if (stse_ret != STSE_OK) {
        APPEND("stse_init error: 0x%04X\n", stse_ret);
        g_idle_add(update_ui_idle, app);
        return NULL;
    }
    APPEND("STSAFE-A120 initialized.\n");

    /* Device authentication */
    stse_ret = stse_device_authenticate(&app->stse_handler,
                                         ca_selfsigned_cert,
                                         STSAFE_CERTIFICATE_ZONE_0,
                                         STSE_STATIC_PRIVATE_KEY_SLOT_0);
    if (stse_ret != STSE_OK) {
        APPEND("stse_device_authenticate error: 0x%04X\n", stse_ret);
        g_idle_add(update_ui_idle, app);
        return NULL;
    }
    APPEND("Device authentication: PASSED\n\n");

    g_mutex_lock(&app->result_mutex);
    app->auth_success = TRUE;
    g_mutex_unlock(&app->result_mutex);

    /* Query data partition table */
    PLAT_UI8 total_partition_count = 0;
    stse_ret = stse_data_storage_get_total_partition_count(&app->stse_handler,
                                                            &total_partition_count);
    if (stse_ret != STSE_OK) {
        APPEND("stse_data_storage_get_total_partition_count error: 0x%04X\n", stse_ret);
        g_idle_add(update_ui_idle, app);
        return NULL;
    }
    APPEND("Data partition count: %u\n\n", total_partition_count);

    stsafea_data_partition_record_t record_table[total_partition_count];
    stse_ret = stse_data_storage_get_partitioning_table(&app->stse_handler,
                                                         total_partition_count,
                                                         record_table,
                                                         (PLAT_UI16)(total_partition_count * sizeof(stsafea_data_partition_record_t)));
    if (stse_ret != STSE_OK) {
        APPEND("stse_data_storage_get_partitioning_table error: 0x%04X\n", stse_ret);
    } else {
        APPEND("%-6s %-8s %-8s %-8s %-10s\n",
               "Zone", "Size", "ReadAC", "UpdateAC", "Counter");
        APPEND("----------------------------------------------\n");
        for (PLAT_UI8 i = 0; i < total_partition_count; i++) {
            APPEND("%-6u %-8u %-8u %-8u %-10u\n",
                   i,
                   record_table[i].data_segment_length,
                   record_table[i].read_ac,
                   record_table[i].update_ac,
                   record_table[i].zone_type);
        }
        APPEND("\n");
    }

    /* Read Zone 0 (certificate zone) — first 64 bytes */
    uint8_t zone0_data[64];
    stse_ret = stse_data_storage_read_data_zone(&app->stse_handler, 0, 0x0000,
                                                 zone0_data, sizeof(zone0_data),
                                                 4, STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        APPEND("stse_data_storage_read_data_zone (zone 0) error: 0x%04X\n", stse_ret);
    } else {
        APPEND("Zone 0 first 64 bytes:\n");
        for (size_t k = 0; k < sizeof(zone0_data); k++) {
            APPEND("%02X ", zone0_data[k]);
            if ((k + 1) % 16 == 0) APPEND("\n");
        }
        APPEND("\n");
    }

#undef APPEND

    g_idle_add(update_ui_idle, app);
    return NULL;
}

/* -----------------------------------------------------------------------
 * Button click callback — spawn worker thread
 * ---------------------------------------------------------------------- */
static void on_authenticate_clicked(GtkButton *btn, gpointer user_data)
{
    AppState *app = (AppState *)user_data;

    app->bus_id = (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(app->spin_bus));

    gtk_widget_set_sensitive(app->btn_authenticate, FALSE);
    gtk_spinner_start(GTK_SPINNER(app->spinner));
    gtk_label_set_text(GTK_LABEL(app->lbl_status), "Authenticating...");

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->txt_results));
    gtk_text_buffer_set_text(buf, "", -1);

    pthread_t tid;
    pthread_create(&tid, NULL, auth_worker_thread, app);
    pthread_detach(tid);
}

/* -----------------------------------------------------------------------
 * UI builder
 * ---------------------------------------------------------------------- */
static void build_ui(AppState *app)
{
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "STSAFE-A120 Authentication Demo");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 640, 500);
    gtk_container_set_border_width(GTK_CONTAINER(app->window), 10);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    /* Title */
    GtkWidget *lbl_title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lbl_title),
                         "<span font_weight='bold' font_size='large'>"
                         "STSAFE-A120 Authentication Demo</span>");
    gtk_box_pack_start(GTK_BOX(vbox), lbl_title, FALSE, FALSE, 0);

    /* Bus ID row */
    GtkWidget *hbox_bus = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), hbox_bus, FALSE, FALSE, 0);
    GtkWidget *lbl_bus = gtk_label_new("I2C Bus ID:");
    gtk_box_pack_start(GTK_BOX(hbox_bus), lbl_bus, FALSE, FALSE, 0);
    GtkAdjustment *adj = gtk_adjustment_new(DEFAULT_I2C_BUS_ID, 0, 10, 1, 1, 0);
    app->spin_bus = gtk_spin_button_new(adj, 1, 0);
    gtk_box_pack_start(GTK_BOX(hbox_bus), app->spin_bus, FALSE, FALSE, 0);

    /* Authenticate button + spinner row */
    GtkWidget *hbox_btn = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), hbox_btn, FALSE, FALSE, 0);
    app->btn_authenticate = gtk_button_new_with_label("Authenticate");
    gtk_box_pack_start(GTK_BOX(hbox_btn), app->btn_authenticate, FALSE, FALSE, 0);
    app->spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(hbox_btn), app->spinner, FALSE, FALSE, 0);
    g_signal_connect(app->btn_authenticate, "clicked", G_CALLBACK(on_authenticate_clicked), app);

    /* Status label */
    app->lbl_status = gtk_label_new("Press 'Authenticate' to start.");
    gtk_box_pack_start(GTK_BOX(vbox), app->lbl_status, FALSE, FALSE, 0);

    /* Scrolled text view for results */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);
    app->txt_results = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->txt_results), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->txt_results), TRUE);
    gtk_container_add(GTK_CONTAINER(scroll), app->txt_results);

    gtk_widget_show_all(app->window);
}

/* -----------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    AppState *app = g_new0(AppState, 1);
    app->bus_id = DEFAULT_I2C_BUS_ID;
    if (argc > 1) app->bus_id = atoi(argv[1]);
    g_mutex_init(&app->result_mutex);

    build_ui(app);
    gtk_main();

    g_mutex_clear(&app->result_mutex);
    g_free(app);
    return 0;
}
