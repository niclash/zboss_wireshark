/* packet-zbee-nwk-gp.c
 * Dissector routines for the ZigBee Green Power Profile (GP)
 * Copyright 2013 DSR Corporation http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Used Owen Kirby's packet-zbee-aps module as a template. Based
 * on ZigBee Cluster Library Specification document 075123r02ZB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*  Include Files */
#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/uat.h>

#include "packet-ieee802154.h"
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-security.h"

#include "packet-zbee-nwk-gp.h"
#include "packet-zbee-nwk-gp-zcl.h"

#include "tvbuff.h"
#include "tvbuff-int.h"

#include <wsutil/wsgcrypt.h>

/*************************/
/* Function Declarations */
/*************************/

/* Initialization */

static void       proto_init_zbee_nwk_gp                                (void);
static void       gp_init_zbee_security                                 (void);
void              proto_register_zbee_nwk_gp                            (void);
void              proto_reg_handoff_zbee_nwk_gp                         (void);
static gboolean   zbee_gp_decrypt_payload(zbee_nwk_green_power_packet *, const gchar *, const gchar, guint8 *, guint, guint,
    guint8 *);
static void       zbee_gp_make_nonce(zbee_nwk_green_power_packet *, gchar *);
extern gboolean   zbee_sec_ccm_decrypt(const gchar *, const gchar *, const gchar *, const gchar *, gchar *, guint, guint,
    guint);

/* Dissector Routines */

static gboolean   dissect_zbee_nwk_heur_gp                              (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
                                                                          void *data _U_);

static void       dissect_zbee_nwk_gp                                   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint      dissect_zbee_nwk_gp_cmd                               (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static guint      dissect_zbee_nwk_gp_cmd_commissioning                 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, guint offset);
static guint      dissect_zbee_nwk_gp_cmd_commissioning_replay          (tvbuff_t *tvb,packet_info *pinfo, proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, guint offset);
static guint      dissect_zbee_nwk_gp_cmd_attr_reporting                (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);
static guint      dissect_zbee_nwk_gp_cmd_channel_request               (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);
static guint      dissect_zbee_nwk_gp_cmd_channel_configuration         (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);
static guint      dissect_zbee_nwk_gp_cmd_move_up_down                  (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);
static guint      dissect_zbee_nwk_gp_cmd_step_up_down                  (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);
static guint      dissect_zbee_nwk_gp_cmd_move_color                    (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);
static guint      dissect_zbee_nwk_gp_cmd_step_color                    (tvbuff_t *tvb, 
                                                                          packet_info *pinfo, 
                                                                          proto_tree *tree, 
                                                                          zbee_nwk_green_power_packet *packet, 
                                                                          guint offset);

/********************/
/* Global Variables */
/********************/

static zbee_nwk_gp_cmd_commissioning_t cmd_hdr;

/* Proto GP Id */
static int proto_zbee_nwk_gp = -1;

/* GP NWK FC */
static int hf_zbee_nwk_gp_frame_type = -1; 
static int hf_zbee_nwk_gp_proto_version = -1;
static int hf_zbee_nwk_gp_auto_commissioning = -1;
static int hf_zbee_nwk_gp_fc_ext = -1;

/* GP NWK FC Extension */
static int hf_zbee_nwk_gp_fc_ext_app_id = -1;
static int hf_zbee_nwk_gp_fc_ext_sec_level = -1;
static int hf_zbee_nwk_gp_fc_ext_sec_key = -1;
static int hf_zbee_nwk_gp_fc_ext_rx_after_tx = -1;
static int hf_zbee_nwk_gp_fc_ext_direction = -1;

/* ZGPD SrcID */
static int hf_zbee_nwk_gp_zgpd_src_id = -1;

/* Security Frame Counter */
static int hf_zbee_nwk_gp_security_frame_counter = -1;

/* Security MIC */
static int hf_zbee_nwk_gp_security_mic_2b = -1;
static int hf_zbee_nwk_gp_security_mic_4b = -1;

/* Payload Subframe */
static int hf_zbee_nwk_gp_command_id = -1;

/* GP Commands */
/* Commissioning */
static int hf_zbee_nwk_gp_cmd_comm_device_id = -1;

static int hf_zbee_nwk_gp_cmd_comm_opt_mac_sec_num_cap = -1;
static int hf_zbee_nwk_gp_cmd_comm_opt_rx_on_cap = -1;
static int hf_zbee_nwk_gp_cmd_comm_opt_panid_req = -1;
static int hf_zbee_nwk_gp_cmd_comm_opt_sec_key_req = -1;
static int hf_zbee_nwk_gp_cmd_comm_opt_fixed_location = -1;
static int hf_zbee_nwk_gp_cmd_comm_opt_ext_opt = -1;

static int hf_zbee_nwk_gp_cmd_comm_ext_opt_sec_level_cap = -1;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_key_type = -1;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_present = -1;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_encr = -1;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_outgoing_counter = -1;

//static int hf_zbee_nwk_gp_cmd_comm_gpd_sec_key = -1;

static int hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic = -1;

static int hf_zbee_nwk_gp_cmd_comm_outgoing_counter = -1;

static int hf_zbee_nwk_gp_cmd_comm_manufacturer_id = -1;
static int hf_zbee_nwk_gp_cmd_comm_manufacturer_dev_id = -1;

/* Commissioning Replay */
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_panid_present = -1;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_key_present = -1;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_key_encr = -1;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_level = -1;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_type = -1;

static int hf_zbee_nwk_gp_cmd_comm_rep_pan_id = -1;

/* Attribute reporting */
static int hf_zbee_nwk_gp_cmd_attr_report_cluster_id = -1;

/* Channel request */
static int hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_1st = -1;
static int hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_2nd = -1;

/* Channel configuration command */
static int hf_zbee_nwk_gp_cmd_channel_configuration = -1;


/* Proto three elements */
static gint ett_zbee_nwk = -1;
static gint ett_zbee_nwk_fcf = -1;
static gint ett_zbee_nwk_fcf_ext = -1;
static gint ett_zbee_nwk_cmd = -1;
static gint ett_zbee_nwk_cmd_options = -1;
static gint ett_zbee_nwk_cmd_cinfo = -1;

static dissector_handle_t   data_handle;
static uat_t *zbee_gp_sec_key_table_uat;

typedef struct {
    gchar *string;
    guint8 byte_order;
    gchar *label;
    guint8 key[ZBEE_SEC_CONST_KEYSIZE];
} uat_key_record_t;

static uat_key_record_t *gp_uat_key_records = NULL;
static guint num_uat_key_records = 0;

static gboolean zbee_gp_security_parse_key(const gchar *key_str, guint8 *key_buf, gboolean byte_order)
{
    int             i, j;
    gchar           temp;
    gboolean        string_mode = FALSE;

    memset(key_buf, 0, ZBEE_SEC_CONST_KEYSIZE);
    if (key_str == NULL) {
        return FALSE;
    }

    if ( (temp = *key_str++) == '"') {
        string_mode = TRUE;
        temp = *key_str++;
    }

    j = byte_order?ZBEE_SEC_CONST_KEYSIZE-1:0;
    for (i=ZBEE_SEC_CONST_KEYSIZE-1; i>=0; i--) {
        if ( string_mode ) {
            if ( g_ascii_isprint(temp) ) {
                key_buf[j] = temp;
                temp = *key_str++;
            } else {
                return FALSE;
            }
        } else {
            if ( (temp == ':') || (temp == '-') || (temp == ' ') ) temp = *(key_str++);

            if ( g_ascii_isxdigit (temp) ) key_buf[j] = g_ascii_xdigit_value(temp)<<4;
            else return FALSE;

            temp = *(key_str++);

            if ( g_ascii_isxdigit (temp) ) key_buf[j] |= g_ascii_xdigit_value(temp);
            else return FALSE;

            temp = *(key_str++);
        }
        if ( byte_order ) {
            j--;
        } else {
            j++;
        }
    } 
    return TRUE;
}

static void* uat_key_record_copy_cb(void* n, const void* o, size_t siz _U_) {
    uat_key_record_t* new_key = (uat_key_record_t *)n;
    const uat_key_record_t* old_key = (uat_key_record_t *)o;

    if (old_key->string) {
        new_key->string = g_strdup(old_key->string);
    } else {
        new_key->string = NULL;
    }
    if (old_key->label) {
        new_key->label = g_strdup(old_key->label);
    } else {
        new_key->label = NULL;
    }
    return new_key;
}

static void uat_key_record_update_cb(void* r, const char** err) {
    uat_key_record_t* rec = (uat_key_record_t *)r;

    if (rec->string == NULL) {
         *err = ep_strdup_printf("Key can't be blank");
    } else {
        g_strstrip(rec->string);
        if (rec->string[0] != 0) {
            *err = NULL;
            if ( !zbee_gp_security_parse_key(rec->string, rec->key, rec->byte_order) ) {
                *err = ep_strdup_printf("Expecting %d hexadecimal bytes or\n"
                        "a %d character double-quoted string", ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
            }
        } else {
            *err = ep_strdup_printf("Key can't be blank");
        }
    }
}

static void uat_key_record_free_cb(void*r) {
    uat_key_record_t* key = (uat_key_record_t *)r;
    if (key->string) g_free(key->string);
    if (key->label) g_free(key->label);
}

static GSList *zbee_gp_keyring = NULL;

static const value_string byte_order_vals[] = {
    { 0, "Normal"},
    { 1, "Reverse"},
    { 0, NULL }
};

UAT_CSTRING_CB_DEF(gp_uat_key_records, string, uat_key_record_t)
UAT_VS_DEF(gp_uat_key_records, byte_order, uat_key_record_t, guint8, 0, "Normal")
UAT_CSTRING_CB_DEF(gp_uat_key_records, label, uat_key_record_t)

/********************/
/* Field Names      */
/********************/

/* Frame Types For Green Power Profile*/
static const value_string zbee_nwk_gp_frame_types[] = {
    { ZBEE_NWK_GP_FCF_DATA,         "Data" },
    { ZBEE_NWK_GP_FCF_MAINTENANCE,  "Maintenance" },
    { 0, NULL }
};

/* Application IDs Names */
static const value_string zbee_nwk_gp_app_id_names[] = {
    { ZBEE_NWK_GP_APP_ID_ZGP,             "ZGP" },
    { ZBEE_NWK_GP_APP_ID_LPED,            "LPED" },
    { 0, NULL }
};

/* GP Directions names */
static const value_string zbee_nwk_gp_directions[] = {
    { ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD,   "From ZGPD" },
    { ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPP,   "From ZGPP" },
    { 0, NULL }
};

/* GP Src IDs Names */
static const value_string zbee_nwk_gp_src_id_names[] = {
    { ZBEE_NWK_GP_ZGPD_SRCID_UNKNOWN,   "Unspecified" },
    { ZBEE_NWK_GP_ZGPD_SRCID_ALL,       "All" },
    { 0, NULL }
};

/* GP Security Levels */
static const value_string zbee_nwk_gp_src_sec_levels_names[] = {
    { ZBEE_NWK_GP_SECURITY_LEVEL_NO,        "No security" },
    { ZBEE_NWK_GP_SECURITY_LEVEL_1LSB,      "1LSB of frame counter and short (2B) MIC only" },
    { ZBEE_NWK_GP_SECURITY_LEVEL_FULL,      "Full (4B) frame counter and full (4B) MIC only" },
    { ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR,  "Encryption & full (4B) frame counter and full (4B) MIC" },
    { 0, NULL }
};

/* GP Security Key Types Names */
static const value_string zbee_nwk_gp_src_sec_keys_type_names[] = {
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_NO_KEY,                             "No key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_ZB_NWK_KEY,                         "ZigBee NWK key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_GPD_GROUP_KEY,                      "GPD group key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_NWK_KEY_DERIVED_GPD_KEY_GROUP_KEY,  "NWK-key derived GPD group key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_PRECONFIGURED_INDIVIDUAL_GPD_KEY,   "Individual, out of the  box GPD key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_DERIVED_INDIVIDUAL_GPD_KEY,         "Derived individual GPD key" },
    { 0, NULL }
};

/* GP Command Names */
static const value_string zbee_nwk_gp_cmd_names[] = {
    /* Table 47 – Payloadless GPDF commands sent by GPD */
    { ZB_GP_CMD_ID_IDENTIFY,              "Identify" },
    { ZB_GP_CMD_ID_SCENE0,                "Scene 0" },
    { ZB_GP_CMD_ID_SCENE1,                "Scene 1" },
    { ZB_GP_CMD_ID_SCENE2,                "Scene 2" },
    { ZB_GP_CMD_ID_SCENE3,                "Scene 3" },
    { ZB_GP_CMD_ID_SCENE4,                "Scene 4" },
    { ZB_GP_CMD_ID_SCENE5,                "Scene 5" },
    { ZB_GP_CMD_ID_SCENE6,                "Scene 6" },
    { ZB_GP_CMD_ID_SCENE7,                "Scene 7" },
    { ZB_GP_CMD_ID_SCENE8,                "Scene 8" },
    { ZB_GP_CMD_ID_SCENE9,                "Scene 9" },
    { ZB_GP_CMD_ID_SCENE10,               "Scene 10" },
    { ZB_GP_CMD_ID_SCENE11,               "Scene 11" },
    { ZB_GP_CMD_ID_SCENE12,               "Scene 12" },
    { ZB_GP_CMD_ID_SCENE13,               "Scene 13" },
    { ZB_GP_CMD_ID_SCENE14,               "Scene 14" },
    { ZB_GP_CMD_ID_SCENE15,               "Scene 15" },
    { ZB_GP_CMD_ID_OFF,                   "Off" },
    { ZB_GP_CMD_ID_ON,                    "On" },
    { ZB_GP_CMD_ID_TOGGLE,                "Toggle" },
    { ZB_GP_CMD_ID_RELEASE,               "Release" },
    { ZB_GP_CMD_ID_LEVEL_CONTROL_STOP,    "Level Control/Stop" },
    { ZB_GP_CMD_ID_MOVE_HUE_STOP,         "Move Hue Stop" },
    { ZB_GP_CMD_ID_MOVE_SATURATION_STOP,  "Move Saturation Stop" },
    { ZB_GP_CMD_ID_LOCK_DOOR,             "Lock Door" },
    { ZB_GP_CMD_ID_UNLOCK_DOOR,           "Unlock Door" },
    { ZB_GP_CMD_ID_PRESS11,               "Press 1 of 1" },
    { ZB_GP_CMD_ID_RELEASE11,             "Release 1 of 1" },
    { ZB_GP_CMD_ID_PRESS12,               "Press 1 of 2" },
    { ZB_GP_CMD_ID_RELEASE12,             "Release 1 of 2" },
    { ZB_GP_CMD_ID_PRESS22,               "Press 2 of 2" },
    { ZB_GP_CMD_ID_RELEASE22,             "Release 2 of 2" },
    { ZB_GP_CMD_ID_SHORT_PRESS11,         "Short press 1 of 1" },
    { ZB_GP_CMD_ID_SHORT_PRESS12,         "Short press 1 of 2" },
    { ZB_GP_CMD_ID_SHORT_PRESS22,         "Short press 2 of 2" },
    { ZB_GP_CMD_ID_DECOMMISSIONING,       "Decommissioning" },
    { ZB_GP_CMD_ID_SUCCESS,               "Success" },

    /* Table 48 – GPDF commands with payload sent by GPD */
    { ZB_GP_CMD_ID_MOVE_UP,                                   "Move Up" },
    { ZB_GP_CMD_ID_MOVE_DOWN,                                 "Move Down" },
    { ZB_GP_CMD_ID_STEP_UP,                                   "Step Up" },
    { ZB_GP_CMD_ID_STEP_DOWN,                                 "Step Down" },
    { ZB_GP_CMD_ID_MOVE_UP_WITH_ON_OFF,                       "Move Up (with On/Off)" },
    { ZB_GP_CMD_ID_MOVE_DOWN_WITH_ON_OFF,                     "Move Down (with On/Off)" },
    { ZB_GP_CMD_ID_STEP_UP_WITH_ON_OFF,                       "Step Up (with On/Off)" },
    { ZB_GP_CMD_ID_STEP_DOWN_WITH_ON_OFF,                     "Step Down (with On/Off)" },
    { ZB_GP_CMD_ID_MOVE_HUE_UP,                               "Move Hue Up" },
    { ZB_GP_CMD_ID_MOVE_HUE_DOWN,                             "Move Hue Down" },
    { ZB_GP_CMD_ID_STEP_HUE_UP,                               "Step Hue Up" },
    { ZB_GP_CMD_ID_STEP_HUW_DOWN,                             "Step Hue Down" },
    { ZB_GP_CMD_ID_MOVE_SATUREATION_UP,                       "Move Saturation Up" },
    { ZB_GP_CMD_ID_MOVE_SATUREATION_DOWN,                     "Move Saturation Down" },
    { ZB_GP_CMD_ID_STEP_SATURATION_UP,                        "Step Saturation Up" },
    { ZB_GP_CMD_ID_STEP_SATURATION_DOWN,                      "Step Saturation Down" },
    { ZB_GP_CMD_ID_MOVE_COLOR,                                "Move Color" },
    { ZB_GP_CMD_ID_STEP_COLOR,                                "Step Color" },
    { ZB_GP_CMD_ID_ATTRIBUTE_REPORTING,                       "Attribute reporting" },
    { ZB_GP_CMD_ID_MANUFACTURE_SPECIFIC_ATTR_REPORTING,       "Manufacturer-specific attribute reporting" },
    { ZB_GP_CMD_ID_MULTI_CLUSTER_REPORTING,                   "Multi-cluster reporting" },
    { ZB_GP_CMD_ID_MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING,  "Manufacturer-specific multi-cluster reporting" },
    { ZB_GP_CMD_ID_REQUEST_ATTRIBUTES,                        "Request Attributes" },
    { ZB_GP_CMD_ID_READ_ATTRIBUTES_RESPONSE,                  "Read Attributes Response" },
    { ZB_GP_CMD_ID_ANY_SENSOR_COMMAND_A0_A3,                  "Any GPD sensor command (0xA0 – 0xA3)" },
    { ZB_GP_CMD_ID_COMMISSIONING,                             "Commissioning" },
    { ZB_GP_CMD_ID_CHANNEL_REQUEST,                           "Channel Request" },

    /* Table 49 – GPDF commands sent to GPD */
    { ZB_GP_CMD_ID_COMMISSIONING_REPLY,     "Commissioning Reply" },
    { ZB_GP_CMD_ID_WRITE_ATTRIBUTES,        "Write Attributes" },
    { ZB_GP_CMD_ID_READ_ATTRIBUTES,         "Read Attributes" },
    { ZB_GP_CMD_ID_CHANNEL_CONFIGURATION,   "Channel Configuration" },

    /* ---  */ 
    
    { 0, NULL }
};

/* GP Device Types Names: Table 50 – List of GPDs for ApplicationID 0b000 and 0b010 */
static const value_string zbee_nwk_gp_device_ids_names[] = {

  /* GP GENERIC */
  { GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_1STATE_SWITCH,    "Generic: GP Simple Generic 1-state Switch" }, 
  { GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_2STATE_SWITCH,    "Generic: GP Simple Generic 2-state Switch " },   
  { GPD_DEVICE_ID_GENERIC_GP_ON_OFF_SWITCH,                   "Generic: GP On/Off Switch" },                   
  { GPD_DEVICE_ID_GENERIC_GP_LEVEL_CONTROL_SWITCH,            "Generic: GP Level Control Switch" },            
  { GPD_DEVICE_ID_GENERIC_GP_SIMPLE_SENSOR,                   "Generic: GP Simple Sensor " },                   
  { GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_1STATE_SWITCH,  "Generic: GP Advanced Generic 1-state Switch" }, 
  { GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_2STATE_SWITCH,  "Generic: GP Advanced Generic 2-state Switch" }, 

  /* GP LIGHTING */
  { GPD_DEVICE_ID_LIGHTING_GP_COLOR_DIMMER_SWITCH,  "Lighting: GP Color Dimmer Switch" },
  { GPD_DEVICE_ID_LIGHTING_GP_LIGHT_SENSOR,         "Lighting: GP Light Sensor" },
  { GPD_DEVICE_ID_LIGHTING_GP_OCCUPANCY_SENSOR,     "Lighting: GP Occupancy Sensor" },

  /* GP CLOSURES */
  { GPD_DEVICE_ID_CLOSURES_GP_DOOR_LOCK_CONTROLLER, "Closures: GP Door Lock Controller" },

   /* HVAC */
  { GPD_DEVICE_ID_HVAC_GP_TEMPERATURE_SENSOR,         "HVAC: GP Temperature Sensor" },
  { GPD_DEVICE_ID_HVAC_GP_PRESSURE_SENSOR,            "HVAC: GP Pressure Sensor" }, 
  { GPD_DEVICE_ID_HVAC_GP_FLOW_SENSOR,                "HVAC: GP Flow Sensor" },
  { GPD_DEVICE_ID_HVAC_GP_INDOOR_ENVIRONMENT_SENSOR,  "HVAC: GP Indoor Environment Sensor" },

  /* Manufacturer specific */
  { GPD_DEVICE_ID_MANUFACTURER_SPECIFIC, "Manufacturer Specific" },

  { 0, NULL }
};

/* GP Manufacturers Names */
static const value_string zbee_nwk_gp_manufacturers_ids_names[] = {
    { 0, NULL }
};

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_nwk_gp
 *  DESCRIPTION
 *      ZigBee protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zbee_nwk_gp(void)
{
    module_t* gp_zbee_prefs = NULL;

    static hf_register_info hf[] = {
            
            /* FC */
            { &hf_zbee_nwk_gp_frame_type,
            { "Frame Type",             "zbee.nwk.gp.frame_type", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_frame_types), ZBEE_NWK_GP_FCF_FRAME_TYPE,
                NULL, HFILL }},

            { &hf_zbee_nwk_gp_proto_version,
            { "Protocol Version",       "zbee.nwk.gp.proto_version", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_GP_FCF_VERSION,
                NULL, HFILL }},
            
            { &hf_zbee_nwk_gp_auto_commissioning,
            { "Auto Commissioning",     "zbee.nwk.gp.autocommissioning", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_AUTO_COMMISSIONING,
                "The Auto Commissioning sub-field indicates if the ZGPD implements the Commissioning GPDF. If set to 0b1, the ZGPD does not implement the Commissioning GPDF. If set to 0b0, the ZGPD does implement the Commissioning GPDF.", HFILL }},
            
            { &hf_zbee_nwk_gp_fc_ext,
            { "NWK Frame Extension",     "zbee.nwk.gp.fc_extension", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_CONTROL_EXTENSION,
                "The NWK Frame Control Extension, if set to 0b1, indicates that the Extended NWK Frame Control field of the GPDF is present.", HFILL }},
           
            /* Exteded FC */ 
            { &hf_zbee_nwk_gp_fc_ext_app_id,
            { "Application ID",         "zbee.nwk.gp.fc_ext_app_id", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_app_id_names), ZBEE_NWK_GP_FCF_EXT_APP_ID,
                NULL, HFILL }},

            { &hf_zbee_nwk_gp_fc_ext_sec_level,
            { "Security Level",         "zbee.nwk.gp.fc_ext_security_level", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_src_sec_levels_names), ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL,
                NULL, HFILL }},

            { &hf_zbee_nwk_gp_fc_ext_sec_key,
            { "Security Key",           "zbee.nwk.gp.fc_ext_security_key", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_EXT_SECURITY_KEY,
                NULL, HFILL }},
            
            { &hf_zbee_nwk_gp_fc_ext_rx_after_tx,
            { "Rx After Tx",            "zbee.nwk.gp.fc_ext_rxaftertx", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_EXT_RX_AFTER_TX,
                NULL, HFILL }},
            
            { &hf_zbee_nwk_gp_fc_ext_direction,
            { "Direction",             "zbee.nwk.gp.fc_ext_direction", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_directions), ZBEE_NWK_GP_FCF_EXT_DIRECTION,
                NULL, HFILL }},

            /* ZGPD SrcID */
            { &hf_zbee_nwk_gp_zgpd_src_id,
            { "Src ID",                "zbee.nwk.gp.source_id", FT_UINT32, BASE_HEX, VALS(zbee_nwk_gp_src_id_names), 0x0,
                "The ZGPDSrcID field carries the unique identifier of the ZGPD, to/by which this GPDF is sent.", HFILL }},
            
            /* Security frame counter */
            { &hf_zbee_nwk_gp_security_frame_counter,
            { "Security Frame Counter", "zbee.nwk.gp.security_frame_counter", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            /* Security MIC */ 
            { &hf_zbee_nwk_gp_security_mic_2b,
            { "Security MIC", "zbee.nwk.gp.security_mic2", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
            
            { &hf_zbee_nwk_gp_security_mic_4b,
            { "Security MIC", "zbee.nwk.gp.security_mic4", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            /* ZGP Application Payload */
            { &hf_zbee_nwk_gp_command_id,
            { "ZGPD CommandId",         "zbee.nwk.gp.command_id", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_cmd_names), 0x0,
                NULL, HFILL }},

            /* ZGP Cmds Payload Items */
            /* Commissioning Command  >>> */
              
              { &hf_zbee_nwk_gp_cmd_comm_device_id,
              { "ZGPD Device ID",       "zbee.nwk.gp.cmd.comm.dev_id", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_device_ids_names), 0x0,
                NULL, HFILL }},
              /* 
              { &hf_zbee_nwk_gp_cmd_comm_gpd_sec_key,
              { "GPD Key",              "zbee.nwk.gp.cmd.comm.gpd_key", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
              */
              
              { &hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic,
              { "GPD Key MIC",          "zbee.nwk.gp.cmd.comm.gpd_key_mic", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
              
              { &hf_zbee_nwk_gp_cmd_comm_outgoing_counter,
              { "GPD Outgoing Counter",  "zbee.nwk.gp.cmd.comm.out_counter", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

              { &hf_zbee_nwk_gp_cmd_comm_manufacturer_id,
              { "Manufacturer ID",  "zbee.nwk.gp.cmd.comm.manufacturer_id", FT_UINT16, BASE_HEX, VALS(zbee_nwk_gp_manufacturers_ids_names), 0x0,
                NULL, HFILL }},
              
              { &hf_zbee_nwk_gp_cmd_comm_manufacturer_dev_id,
              { "Manufacturer DeviceID",  "zbee.nwk.gp.cmd.comm.manufacturer_dev_id", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},


              /* Options bitfield */
              { &hf_zbee_nwk_gp_cmd_comm_opt_mac_sec_num_cap,
              { "MAC Sequence number capability",   "zbee.nwk.gp.cmd.comm.opt.mac_seq", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MAC_SEQ,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_opt_rx_on_cap,
              { "RxOnCapability",                   "zbee.nwk.gp.cmd.comm.opt.rxon_cap", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_RX_ON_CAP,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_opt_panid_req,
              { "PANId request",                    "zbee.nwk.gp.cmd.comm.opt.panid_req", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_PAN_ID_REQ,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_opt_sec_key_req,
              { "GP Security Key Request",          "zbee.nwk.gp.cmd.comm.opt.seq_key_req", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_GP_SEC_KEY_REQ,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_opt_fixed_location,
              { "Fixed Location",                   "zbee.nwk.gp.cmd.comm.opt.fix_location", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_FIXED_LOCATION,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_opt_ext_opt,
              { "Extended Option Field",            "zbee.nwk.gp.cmd.comm.opt.ext_opt_field", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS,
                NULL, HFILL }},

              /* Extended Options bitfield */
              { &hf_zbee_nwk_gp_cmd_comm_ext_opt_sec_level_cap,
              { "Security Level Capabilities",       "zbee.nwk.gp.cmd.comm.ext_opt.seclevel_cap", FT_UINT8, BASE_HEX, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_SEC_LEVEL_CAP,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_ext_opt_key_type,
              { "Key Type",       "zbee.nwk.gp.cmd.comm.ext_opt.key_type", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_src_sec_keys_type_names), ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_KEY_TYPE,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_present,
              { "GPD Key Present",   "zbee.nwk.gp.cmd.comm.ext_opt.gpd_key_present", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_encr,
              { "GPD Key Encryption",   "zbee.nwk.gp.cmd.comm.ext_opt.gpd_key_encr", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_ext_opt_outgoing_counter,
              { "GPD Outgoing present",   "zbee.nwk.gp.cmd.comm.ext_opt.gpd_outcounter", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNETR,
                NULL, HFILL }},
            
            /* Commissioning Command <<< */

            /* Commissioning Replay Command >>> */
              
            /* Pan ID Field */             
            { &hf_zbee_nwk_gp_cmd_comm_rep_pan_id,
              { "Manufacturer ID", "zbee.nwk.gp.cmd.comm_replay.pan_id", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

              /* Options field */
              { &hf_zbee_nwk_gp_cmd_comm_rep_opt_panid_present,
              { "PANID Present", "zbee.nwk.gp.cmd.comm_replay.opt.pan_id_present", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_key_present,
              { "GPD Security Key Present", "zbee.nwk.gp.cmd.comm_replay.opt.sec_key_present", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_rep_opt_key_encr,
              { "GPD Key Encryption", "zbee.nwk.gp.cmd.comm_replay.opt.sec_key_encr", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_level,
              { "Security Level", "zbee.nwk.gp.cmd.comm_replay.opt.sec_level", FT_UINT8, BASE_HEX, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL,
                NULL, HFILL }},
              { &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_type,
              { "Key Type", "zbee.nwk.gp.cmd.comm_replay.opt.key_type", FT_UINT8, BASE_HEX, NULL, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_TYPE,
                NULL, HFILL }},

            /* Commissioning Replay Command <<< */

            /* Attribute reporting */
            { &hf_zbee_nwk_gp_cmd_attr_report_cluster_id,
            { "ZigBee Cluster ID",   "zbee.nwk.gp.cmd.comm.attr_report", FT_UINT16, BASE_HEX, VALS(zbee_aps_cid_names), 0x0, 
                NULL, HFILL }},

            /* Channel request */
            { &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_1st,
            { "Rx channel in the next attempt", "zbee.nwk.gp.cmd.ch_req.1st", FT_UINT8, BASE_HEX, NULL, ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_1ST,
                NULL, HFILL }},
            { &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_2nd,
            { "Rx channel in the second next attempt", "zbee.nwk.gp.ch_req.2nd", FT_UINT8, BASE_HEX, NULL, ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_2ND,
                NULL, HFILL }},
            
            /* Channel configuration >>> */
            { &hf_zbee_nwk_gp_cmd_channel_configuration,
            { "Operation channel", "zbee.nwk.gp.cmd.configuration_ch.operation_ch", FT_UINT8, BASE_HEX, NULL, ZBEE_NWK_GP_CMD_CHANNEL_CONFIGURATION_OPERATION_CH,
                NULL, HFILL }},
    };

    /*  NWK Layer subtrees */
    static gint *ett[] = {
        &ett_zbee_nwk,
        &ett_zbee_nwk_fcf,
        &ett_zbee_nwk_fcf_ext,
        &ett_zbee_nwk_cmd,
        &ett_zbee_nwk_cmd_options,
        &ett_zbee_nwk_cmd_cinfo
    };

    static uat_field_t key_uat_fields[] = {
        UAT_FLD_CSTRING(gp_uat_key_records, string, "Key", "A 16-byte key."),
        UAT_FLD_VS(gp_uat_key_records, byte_order, "Byte Order", byte_order_vals, "Byte order of key."),
        UAT_FLD_LSTRING(gp_uat_key_records, label, "Label", "User label for key."),
        UAT_END_FIELDS
    };

    proto_zbee_nwk_gp = proto_register_protocol("ZigBee Green Power Profile", "ZigBee Green Power", ZBEE_PROTOABBREV_NWK_GP);

    if (gp_zbee_prefs == NULL) {
        gp_zbee_prefs = prefs_register_protocol(proto_zbee_nwk_gp, NULL);
    }

    zbee_gp_sec_key_table_uat = uat_new("ZigBee GP Security Keys",
                                     sizeof(uat_key_record_t),
                                     "zigbee_gp_keys",
                                     TRUE,
                                     (void**)&gp_uat_key_records,
                                     &num_uat_key_records,
                                     UAT_AFFECTS_DISSECTION, 
                                     NULL,
                                     uat_key_record_copy_cb,
                                     uat_key_record_update_cb,
                                     uat_key_record_free_cb,
                                     NULL,
                                     key_uat_fields
                                    );

    prefs_register_uat_preference(gp_zbee_prefs,
                                  "gp_key_table",
                                  "Pre-configured GP Security Keys",
                                  "Pre-configured GP Security Keys.",
                                  zbee_gp_sec_key_table_uat
                                 );

    register_init_routine(gp_init_zbee_security);
    register_init_routine(proto_init_zbee_nwk_gp);

    /* Register the protocol with Wireshark. */
    proto_register_field_array(proto_zbee_nwk_gp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissectors with Wireshark. */
    register_dissector(ZBEE_PROTOABBREV_NWK_GP, dissect_zbee_nwk_gp, proto_zbee_nwk_gp);
} /* proto_register_zbee_nwk_gp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_nwk_gp
 *  DESCRIPTION
 *      Registers the zigbee dissector with Wireshark.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_nwk_gp(void)
{
    /* Find the other dissectors we need. */
    data_handle     = find_dissector("data");

    /* Register our dissector with IEEE 802.15.4 */
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_zbee_nwk_heur_gp, proto_zbee_nwk_gp);
} /* proto_reg_handoff_zbee */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_init_zbee_nwk_gp
 *  DESCRIPTION
 *      Init routine for the nwk dissector. Creates a
 *      hash table for mapping 16-bit to 64-bit addresses and
 *      populates it with static address pairs from a UAT
 *      preference table.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
proto_init_zbee_nwk_gp(void)
{

} /* proto_init_zbee_nwk_gp */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_heur_gp
 *  DESCRIPTION
 *      Heuristic interpreter for the ZigBee Green Power network dissectors.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      Boolean value, whether it handles the packet or not.
 *---------------------------------------------------------------
 */
static gboolean
dissect_zbee_nwk_heur_gp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gboolean ret = FALSE;
    ieee802154_packet *packet = (ieee802154_packet *)(pinfo->private_data);

    do {
      /* Skip ZigBee beacons */ 
      if ( (packet->frame_type == IEEE802154_FCF_BEACON) &&
           (tvb_get_guint8(tvb, 0) == ZBEE_NWK_BEACON_PROCOL_ID) ) {
        break;
      }
      /* ZigBee GP: In order to allow for GPD mobility and make use of the 
       * built-in  receiver redundancy, the GPDF originating from the GPD 
       * can be sent with MAC Dest PANID and MAC Dest Address set to 0xffff.
       */
      if (packet->dst_pan == IEEE802154_BCAST_PAN 
          && packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT
          && packet->dst16 == IEEE802154_BCAST_ADDR
          && packet->frame_type != IEEE802154_FCF_BEACON
          && packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) {
        dissect_zbee_nwk_gp(tvb, pinfo, tree);
        ret = TRUE;
        break;
      }
      /* All ZigBee 2006, 2007, PRO frames must always have a 16-bit source address. */
      if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) {
        ret = TRUE;
        break;
      }
    } while (FALSE);

    return ret;
} /* dissect_zbee_nwk_heur_gp */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp
 *  DESCRIPTION
 *      ZigBee NWK packet Wireshark dissection routine for Green Power Profile.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */

static void
dissect_zbee_nwk_gp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t                      *payload_tvb  = NULL;

    proto_item                    *proto_root   = NULL;
    proto_item                    *ti           = NULL;
    proto_tree                    *nwk_tree     = NULL;
    proto_tree                    *field_tree   = NULL;

    zbee_nwk_green_power_packet   packet;
    guint                         offset = 0;
    guint8                        fcf;
    guint8                        *dec_buffer;
    guint8                        *enc_buffer;
    gboolean                      gp_decrypted;
    GSList                        *GSList_i;
    key_record_t                  *key_rec = NULL;
    
    memset(&packet, 0, sizeof(packet));

    /* Add ourself to the protocol column, clear the info column, and create the protocol tree. */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee Green Power");
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_clear(pinfo->cinfo, COL_INFO);
    }
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_zbee_nwk_gp, tvb, offset, tvb_length(tvb), "ZGP stub NWK Header");
        nwk_tree = proto_item_add_subtree(proto_root, ett_zbee_nwk);
    }

    enc_buffer = (guint8 *)ep_tvb_memdup(tvb, 0, tvb_length(tvb));

    /* Get and parse the FCF */
    fcf = tvb_get_guint8(tvb, offset);
    
    packet.frame_type = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_FRAME_TYPE);
    packet.protocol_version = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_VERSION);
    packet.auto_commissioning = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_AUTO_COMMISSIONING);
    packet.nwk_frame_control_extension = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_CONTROL_EXTENSION);
    
    pinfo->zbee_stack_vers = packet.protocol_version;

    /* Display the FCF. */
    if (tree) {
        /* Create a subtree for the FCF. */
        ti = proto_tree_add_text(nwk_tree, tvb, offset, sizeof(guint8), "Frame Control Field: %s (0x%02x)", val_to_str(packet.frame_type, zbee_nwk_gp_frame_types, "Unknown"), fcf);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_fcf);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_frame_type, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_FRAME_TYPE);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_proto_version, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_VERSION);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_auto_commissioning, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_AUTO_COMMISSIONING);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_fc_ext, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_CONTROL_EXTENSION);
    }
    offset += sizeof(fcf);

    /* Add the frame type to the info column and protocol root. */
    if (tree) {
        proto_item_append_text(proto_root, " %s", val_to_str(packet.frame_type, zbee_nwk_gp_frame_types, "Unknown Type"));
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet.frame_type, zbee_nwk_gp_frame_types, "Reserved Frame Type"));
    }
    
    /* Display Ext FCF if needed */
    if (packet.nwk_frame_control_extension) {
      fcf = tvb_get_guint8(tvb, offset);

      packet.application_id = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_APP_ID);
      packet.security_level = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL);
      packet.security_key_present = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_SECURITY_KEY);
      packet.rx_after_tx = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_RX_AFTER_TX);
      packet.direction = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_DIRECTION);

      /* Create a subtree for the extended FCF. */
      if (tree) {
        ti = proto_tree_add_text(nwk_tree, tvb, offset, sizeof(guint8), "Extended NWK Frame Control Field");
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_fcf_ext);
        /* Add the fields. */
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_fc_ext_app_id, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_EXT_APP_ID);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_fc_ext_sec_level, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_fc_ext_sec_key, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_EXT_SECURITY_KEY);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_fc_ext_rx_after_tx, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_EXT_RX_AFTER_TX);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_fc_ext_direction, tvb, offset, sizeof(guint8), fcf & ZBEE_NWK_GP_FCF_EXT_DIRECTION);
      }
      offset += sizeof(fcf);
    }

    /* Display if needed GPD Src Id */
    if ( (packet.frame_type == ZBEE_NWK_GP_FCF_DATA && !packet.nwk_frame_control_extension) 
         || (packet.frame_type == ZBEE_NWK_GP_FCF_DATA && packet.nwk_frame_control_extension && packet.application_id == ZBEE_NWK_GP_APP_ID_DEFAULT)
         || (packet.frame_type == ZBEE_NWK_GP_FCF_MAINTENANCE && packet.nwk_frame_control_extension && packet.application_id == ZBEE_NWK_GP_APP_ID_DEFAULT && tvb_get_guint8(tvb, offset) != ZB_GP_CMD_ID_CHANNEL_CONFIGURATION) ) {
      packet.source_id = tvb_get_letohl(tvb, offset);
      if (tree) {
        proto_tree_add_uint(nwk_tree, hf_zbee_nwk_gp_zgpd_src_id, tvb, offset, sizeof(guint32), packet.source_id);
      }
      if (tree) {
        proto_item_append_text(proto_root, ", GPD Src ID: 0x%04x", packet.source_id);
      }
      if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", GPD Src ID: 0x%04x", packet.source_id);
      }
      offset += sizeof(guint32);
    }

    /* Display if needed Security Frame Counter Field */
    packet.mic_size = 0;
    if (packet.nwk_frame_control_extension) {
      if (packet.application_id == ZBEE_NWK_GP_APP_ID_DEFAULT || packet.application_id == ZBEE_NWK_GP_APP_ID_ZGP) {
        if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_1LSB) {
          packet.mic_size = sizeof(guint16);
        } else if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULL || packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
          /* Get Security Frame Counter And Display It */
          packet.mic_size = sizeof(guint32);
          packet.security_frame_counter = tvb_get_letohl(tvb, offset);
          if (tree) {
            proto_tree_add_uint(nwk_tree, hf_zbee_nwk_gp_security_frame_counter, tvb, offset, sizeof(guint32), packet.security_frame_counter);
          }
          offset += sizeof(guint32);
        }
      }
    }

    /* Parse Application Payload */
    packet.payload_offset = offset;
    packet.payload_len = tvb_length(tvb) - offset - packet.mic_size;

    /* Ensure that the payload exists */
    if (packet.payload_len <= 0) {
      expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_ERROR, "Missing Payload");
      THROW(BoundsError);
      return;
    }

    /* OK, payload exist */

    /* Parse MIC field if needed */
    if (packet.mic_size == sizeof(guint16)) {
      packet.mic = tvb_get_letohs(tvb, offset + packet.payload_len);
    } else if (packet.mic_size == sizeof(guint32)) {
      packet.mic = tvb_get_letohl(tvb, offset + packet.payload_len);
    }

    payload_tvb = tvb_new_subset(tvb, offset, packet.payload_len, packet.payload_len);
    if (packet.security_level != ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
        dissect_zbee_nwk_gp_cmd(payload_tvb, pinfo, nwk_tree);
    }
    offset += packet.payload_len;

    /* Display MIC field if needed */
    if (packet.mic_size) {
      if (tree) {
        proto_tree_add_uint(nwk_tree,
          (packet.mic_size == sizeof(guint32)) ? (hf_zbee_nwk_gp_security_mic_4b) : (hf_zbee_nwk_gp_security_mic_2b),
          tvb, offset, packet.mic_size, packet.mic);
      }
      offset += packet.mic_size;
    }

    /* Save packet data */
    pinfo->private_data = (void *)&packet;

    if ((offset < tvb_length(tvb)) && (packet.security_level != ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR)) {
      expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_ERROR, "Data overflow");
      THROW(BoundsError);
    }
    
    if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
        dec_buffer = (guint8 *)g_malloc(packet.payload_len);
        gp_decrypted = FALSE;
        if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
            GSList_i = zbee_gp_keyring;
            while (GSList_i && !gp_decrypted) {
                gp_decrypted = zbee_gp_decrypt_payload(&packet, enc_buffer, offset - packet.payload_len - packet.mic_size,
                    dec_buffer, packet.payload_len, packet.mic_size, ((key_record_t *)(GSList_i->data))->key);
                if (!gp_decrypted) {
                    GSList_i = g_slist_next(GSList_i);
                }
            }
        }
        if ( gp_decrypted ) {
            payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, packet.payload_len, packet.payload_len);
            tvb_set_free_cb(payload_tvb, g_free);
            add_new_data_source(pinfo, payload_tvb, "Decrypted GP Payload");

            dissect_zbee_nwk_gp_cmd(payload_tvb, pinfo, nwk_tree);

            return payload_tvb;
        } else {
            /* Add expert info. */
            expert_add_info_format(pinfo, nwk_tree, PI_UNDECODED, PI_WARN, "Undecoded payload");
            payload_tvb = tvb_new_subset(tvb, offset - packet.payload_len - packet.mic_size, packet.payload_len, -1);
            call_dissector(data_handle, payload_tvb, pinfo, tree);
            /* Couldn't decrypt, so return NULL. */
            return NULL;
        }
        g_free(dec_buffer);
    }
} /* dissect_zbee_nwk_gp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      guint               - payload processed offset
 *---------------------------------------------------------------
 */
static guint dissect_zbee_nwk_gp_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *cmd_tree = NULL;
    proto_item  *cmd_root = NULL;

    zbee_nwk_green_power_packet *packet = (zbee_nwk_green_power_packet *)(pinfo->private_data);

    guint       offset = 0;
    guint8      cmd_id = tvb_get_guint8(tvb, offset);

    /* Save incoming command Id */
    if (packet) {
      packet->command_id = cmd_id;
    }

    /* Create a subtree for this command. */
    if (tree) {
      cmd_root = proto_tree_add_text(tree, tvb, offset, tvb_length(tvb), "Command Frame: %s", val_to_str(cmd_id, zbee_nwk_gp_cmd_names, "Unknown"));
      cmd_tree = proto_item_add_subtree(cmd_root, ett_zbee_nwk_cmd);

      /* Add the command ID. */
      proto_tree_add_uint(cmd_tree, hf_zbee_nwk_gp_command_id, tvb, offset, sizeof(guint8), cmd_id);
    }
    offset += sizeof(guint8);

    /* Add the command name to the info column. */
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmd_id, zbee_nwk_gp_cmd_names, "Unknown Command"));
    }

    /* Handle the command. */
    
    /* Support following devices:
     * - Door Lock Controller (cmd ids: 0x50-0x51);
     * - GP Temperature Sensor (cmd ids: 0xE0,0xA0-0xA3);
     * - GP Flow Sensor (cmd ids: 0xE0,0xA0-0xA3);
     *   See table: Table 51 – List of GPD commands (rev. 24);
     */
    switch(cmd_id) {
      /* Table 47 – Payloadless GPDF commands sent by GPD */
      case ZB_GP_CMD_ID_IDENTIFY:
      case ZB_GP_CMD_ID_SCENE0:       
      case ZB_GP_CMD_ID_SCENE1:        
      case ZB_GP_CMD_ID_SCENE2:        
      case ZB_GP_CMD_ID_SCENE3:               
      case ZB_GP_CMD_ID_SCENE4:        
      case ZB_GP_CMD_ID_SCENE5:        
      case ZB_GP_CMD_ID_SCENE6:        
      case ZB_GP_CMD_ID_SCENE7:        
      case ZB_GP_CMD_ID_SCENE8:        
      case ZB_GP_CMD_ID_SCENE9:        
      case ZB_GP_CMD_ID_SCENE10:        
      case ZB_GP_CMD_ID_SCENE11:       
      case ZB_GP_CMD_ID_SCENE12:       
      case ZB_GP_CMD_ID_SCENE13:       
      case ZB_GP_CMD_ID_SCENE14:       
      case ZB_GP_CMD_ID_SCENE15:       
      case ZB_GP_CMD_ID_OFF:       
      case ZB_GP_CMD_ID_ON:           
      case ZB_GP_CMD_ID_TOGGLE:            
      case ZB_GP_CMD_ID_RELEASE:        
      case ZB_GP_CMD_ID_LEVEL_CONTROL_STOP:
      case ZB_GP_CMD_ID_MOVE_HUE_STOP:
      case ZB_GP_CMD_ID_MOVE_SATURATION_STOP: 
      case ZB_GP_CMD_ID_LOCK_DOOR:
      case ZB_GP_CMD_ID_UNLOCK_DOOR:     
      case ZB_GP_CMD_ID_PRESS11:   
      case ZB_GP_CMD_ID_RELEASE11:       
      case ZB_GP_CMD_ID_PRESS12:     
      case ZB_GP_CMD_ID_RELEASE12:       
      case ZB_GP_CMD_ID_PRESS22:     
      case ZB_GP_CMD_ID_RELEASE22:       
      case ZB_GP_CMD_ID_SHORT_PRESS11:     
      case ZB_GP_CMD_ID_SHORT_PRESS12: 
      case ZB_GP_CMD_ID_SHORT_PRESS22: 
      case ZB_GP_CMD_ID_DECOMMISSIONING: 
      case ZB_GP_CMD_ID_SUCCESS:
        break;

      /* Table 48 – GPDF commands with payload sent by GPD */
      case ZB_GP_CMD_ID_MOVE_UP:
      case ZB_GP_CMD_ID_MOVE_DOWN:
      case ZB_GP_CMD_ID_MOVE_UP_WITH_ON_OFF:
      case ZB_GP_CMD_ID_MOVE_DOWN_WITH_ON_OFF:
      case ZB_GP_CMD_ID_MOVE_HUE_UP:
      case ZB_GP_CMD_ID_MOVE_HUE_DOWN:
      case ZB_GP_CMD_ID_MOVE_SATUREATION_UP:
      case ZB_GP_CMD_ID_MOVE_SATUREATION_DOWN:
        offset = dissect_zbee_nwk_gp_cmd_move_up_down(tvb, pinfo, cmd_tree, packet, offset);
        break;
      case ZB_GP_CMD_ID_STEP_UP:
      case ZB_GP_CMD_ID_STEP_DOWN:
      case ZB_GP_CMD_ID_STEP_UP_WITH_ON_OFF:
      case ZB_GP_CMD_ID_STEP_DOWN_WITH_ON_OFF:
      case ZB_GP_CMD_ID_STEP_HUE_UP:
      case ZB_GP_CMD_ID_STEP_HUW_DOWN:
      case ZB_GP_CMD_ID_STEP_SATURATION_UP:
      case ZB_GP_CMD_ID_STEP_SATURATION_DOWN:
        offset = dissect_zbee_nwk_gp_cmd_step_up_down(tvb, pinfo, cmd_tree, packet, offset);
        break;
      case ZB_GP_CMD_ID_MOVE_COLOR:
        offset = dissect_zbee_nwk_gp_cmd_move_color(tvb, pinfo, cmd_tree, packet, offset);
        break;
      case ZB_GP_CMD_ID_STEP_COLOR:
        offset = dissect_zbee_nwk_gp_cmd_step_color(tvb, pinfo, cmd_tree, packet, offset);
        break;
      case ZB_GP_CMD_ID_ATTRIBUTE_REPORTING:
        offset = dissect_zbee_nwk_gp_cmd_attr_reporting(tvb, pinfo, cmd_tree, packet, offset); 
        break;
      case ZB_GP_CMD_ID_MANUFACTURE_SPECIFIC_ATTR_REPORTING:
      case ZB_GP_CMD_ID_MULTI_CLUSTER_REPORTING:
      case ZB_GP_CMD_ID_MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING:
      case ZB_GP_CMD_ID_REQUEST_ATTRIBUTES:
      case ZB_GP_CMD_ID_READ_ATTRIBUTES_RESPONSE:
      case ZB_GP_CMD_ID_ANY_SENSOR_COMMAND_A0_A3:
        //TODO: implemention
        break;
      case ZB_GP_CMD_ID_COMMISSIONING:          
        offset = dissect_zbee_nwk_gp_cmd_commissioning(tvb, pinfo, cmd_tree, packet, offset);
        break;
      case ZB_GP_CMD_ID_CHANNEL_REQUEST:
        offset = dissect_zbee_nwk_gp_cmd_channel_request(tvb, pinfo, cmd_tree, packet, offset);
        break;        

      /* Table 49 – GPDF commands sent to GPD */
      case ZB_GP_CMD_ID_COMMISSIONING_REPLY:
        offset = dissect_zbee_nwk_gp_cmd_commissioning_replay(tvb, pinfo, cmd_tree, packet, offset);
        break;
      case ZB_GP_CMD_ID_WRITE_ATTRIBUTES:
      case ZB_GP_CMD_ID_READ_ATTRIBUTES:
        //TODO: implementation
        break;
      case ZB_GP_CMD_ID_CHANNEL_CONFIGURATION:
        offset = dissect_zbee_nwk_gp_cmd_channel_configuration(tvb, pinfo, cmd_tree, packet, offset);
        break;
      
      /* Unknown Command */
      default:
        break;
    } /* switch */
    
    if (tree && offset < tvb_length(tvb)) {
      if (cmd_hdr.device_id == GPD_DEVICE_ID_MANUFACTURER_SPECIFIC || cmd_hdr.options.manufacturer_data_present) {
        if (tvb_get_ntohs(tvb, offset) == 0xD010) {
          proto_tree_add_text(cmd_tree, tvb, offset, 2, "Device manufacturer: GreenPeak");
          offset += 2;
          proto_tree_add_text(cmd_tree, tvb, offset, 1,
            val_to_str(tvb_get_guint8(tvb, offset), zbee_nwk_gp_device_ids_names, "Unknown model"));
          offset += 1;
        }
      }
    }

    /* There is excess data in the packet. */
    if (offset < tvb_length(tvb)) {
      /* There are leftover bytes! */
      guint       leftover_len    = tvb_length(tvb) - offset;
      tvbuff_t    *leftover_tvb   = tvb_new_subset(tvb, offset, leftover_len, leftover_len);
      proto_tree  *root           = NULL;

      /* Correct the length of the command tree. */
      if (tree) {
        root = proto_tree_get_root(tree);
        proto_item_set_len(cmd_root, offset);
      }

      /* Dump the leftover to the data dissector. */
      call_dissector(data_handle, leftover_tvb, pinfo, root);
    }

    return offset;
} /* dissect_zbee_nwk_gp_cmd */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_commissioning
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_commissioning(tvbuff_t *tvb, 
    packet_info *pinfo, 
    proto_tree *tree, 
    zbee_nwk_green_power_packet *packet, 
    guint offset)
{
    proto_item                      *ti = NULL;
    proto_tree                      *field_tree = NULL;

    guint8                          tmp = 0;


    (void)pinfo;
    (void)packet;

    memset(&cmd_hdr, 0, sizeof(cmd_hdr));
   
    /* Get Device ID  and display */ 
    cmd_hdr.device_id = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_device_id, tvb, offset, sizeof(guint8), cmd_hdr.device_id);
    }
    offset += sizeof(guint8);

    /* Get Options Field, build subtree and display results */
    tmp = tvb_get_guint8(tvb, offset);
    cmd_hdr.options.mac_seq_num_capability    = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MAC_SEQ);
    cmd_hdr.options.rx_on_capability          = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_RX_ON_CAP);
    cmd_hdr.options.pan_id_request            = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_PAN_ID_REQ);
    cmd_hdr.options.gp_sec_key_request        = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_GP_SEC_KEY_REQ);
    cmd_hdr.options.fixed_location            = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_FIXED_LOCATION);
    cmd_hdr.options.extended_options          = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS);
    cmd_hdr.options.manufacturer_data_present = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MANUFACTURER_INFO);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Options Field: 0x%01x", tmp);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);
        
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_opt_mac_sec_num_cap, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MAC_SEQ);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_opt_rx_on_cap, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_RX_ON_CAP);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_opt_panid_req, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_PAN_ID_REQ);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_opt_sec_key_req, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_GP_SEC_KEY_REQ);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_opt_fixed_location, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_FIXED_LOCATION);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_opt_ext_opt, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS);
    }
    offset += sizeof(guint8);

    if (cmd_hdr.options.extended_options) {
      /* Get Extended Options Field, build subtree and display results */
      tmp = tvb_get_guint8(tvb, offset);
      cmd_hdr.extended_options.sec_level_capabilities       = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_SEC_LEVEL_CAP);
      cmd_hdr.extended_options.key_type                     = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_KEY_TYPE);
      cmd_hdr.extended_options.gpd_key_present              = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT);
      cmd_hdr.extended_options.gpd_key_encryption           = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR);
      cmd_hdr.extended_options.gpd_outgoing_counter_present = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNETR);
      if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Extended Options Field: 0x%01x", tmp);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);
        
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_cmd_comm_ext_opt_sec_level_cap, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_SEC_LEVEL_CAP);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_cmd_comm_ext_opt_key_type, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_KEY_TYPE);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_present, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_encr, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_ext_opt_outgoing_counter, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNETR);
      }
      offset += sizeof(guint8);

      /* Get Security Key and display if needed */
      if (cmd_hdr.extended_options.gpd_key_present) {
        guint ii = 0, ff = 0;
        for (ii = 0; ii < sizeof(cmd_hdr.security_key); ++ii) {
          cmd_hdr.security_key[ii] = tvb_get_guint8(tvb, offset+ff);  
          ff += sizeof(guint8);
        }
        if (tree) {
          proto_tree_add_text(tree, tvb, offset, sizeof(cmd_hdr.security_key), "Security key: %s", (char*)cmd_hdr.security_key);
        }
        offset += ff;
      }
      
      /* Get Security MIC and display if needed */
      if (cmd_hdr.extended_options.gpd_key_encryption) {
        cmd_hdr.gpd_key_mic = tvb_get_letohl(tvb, offset);
        if (tree) {
          proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic, tvb, offset, sizeof(guint32), cmd_hdr.gpd_key_mic);
        }
        offset += sizeof(guint32);
      }
      
      /* Get GPD Outgoing Frame Counter and display if needed */
      if (cmd_hdr.extended_options.gpd_outgoing_counter_present) {
        cmd_hdr.gpd_outgoing_counter = tvb_get_letohl(tvb, offset);
        if (tree) {
          proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_outgoing_counter, tvb, offset, sizeof(guint32), cmd_hdr.gpd_outgoing_counter);
        }
        offset += sizeof(guint32);
      }

      /* Display if needed manufacturer specific data */
      if (cmd_hdr.device_id == GPD_DEVICE_ID_MANUFACTURER_SPECIFIC
          || cmd_hdr.options.manufacturer_data_present) {
        /* Get Manufacturer ID */
        cmd_hdr.manufacturer_id = tvb_get_letohs(tvb, offset);
        if (tree) {
          proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_manufacturer_id, tvb, offset, sizeof(guint16), cmd_hdr.manufacturer_id);
        }
        offset += sizeof(guint16);

        /* Get Manufacturer Device ID */
        cmd_hdr.manufacturer_device_id = tvb_get_guint8(tvb, offset);
        if (tree) {
          proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_manufacturer_id, tvb, offset, sizeof(guint8), cmd_hdr.manufacturer_device_id);
        }

        offset += sizeof(guint8);
      }
    }

    return offset;
} /* dissect_zbee_nwk_gp_cmd_commissioning */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_commissioning_replay
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_commissioning_replay(tvbuff_t *tvb, 
    packet_info *pinfo, 
    proto_tree *tree, 
    zbee_nwk_green_power_packet *packet, 
    guint offset)
{
    proto_item                      *ti = NULL;
    proto_tree                      *field_tree = NULL;

    guint8                          tmp = 0;

    zbee_nwk_gp_cmd_commissioning_replay_t cmd_hdr;

    (void)pinfo;
    (void)packet;

    memset(&cmd_hdr, 0, sizeof(cmd_hdr));
   
    /* Get Options Field, build subtree and display results */
    tmp = tvb_get_guint8(tvb, offset);
    cmd_hdr.options.panid_present     = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT);
    cmd_hdr.options.sec_key_present   = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT);
    cmd_hdr.options.sec_key_ecryption = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR);
    cmd_hdr.options.security_level    = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL);
    cmd_hdr.options.key_type          = zbee_get_bit_field(tmp, ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_TYPE);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Options Field: 0x%01x", tmp);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_rep_opt_panid_present,   tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_key_present, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT);
        proto_tree_add_boolean(field_tree, hf_zbee_nwk_gp_cmd_comm_rep_opt_key_encr,        tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR);
        proto_tree_add_uint(field_tree,    hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_level,       tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL);
        proto_tree_add_uint(field_tree,    hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_type,        tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_TYPE);
    }
    offset += sizeof(guint8);

    /* Parse and display security Pan ID value */
    if (cmd_hdr.options.panid_present) {
      cmd_hdr.pan_id = tvb_get_letohs(tvb, offset);
      if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_rep_pan_id, tvb, offset, sizeof(guint16), cmd_hdr.pan_id);
      }
      offset += sizeof(guint16);
    }

    /* Parse and display security key */
    if (cmd_hdr.options.sec_key_present) {
      guint ii = 0, ff = 0;
      for (ii = 0; ii < sizeof(cmd_hdr.security_key); ++ii) {
        cmd_hdr.security_key[ii] = tvb_get_guint8(tvb, offset+ff);  
        ff += sizeof(guint8);
      }
      if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(cmd_hdr.security_key), "Security key: %s", (char*)cmd_hdr.security_key);
      }
      offset += ff;
    }

    /* Parse and display security MIC */
    if (cmd_hdr.options.sec_key_ecryption && cmd_hdr.options.sec_key_present) {
      cmd_hdr.gpd_key_mic = tvb_get_letohl(tvb, offset);
      if (tree) {
        proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic, tvb, offset, sizeof(guint32), cmd_hdr.gpd_key_mic);
      }
      offset += sizeof(guint32);
    }

    return offset;
} /* dissect_zbee_nwk_gp_cmd_commissioning_replay */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_attr_reporting
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_attr_reporting(tvbuff_t *tvb, 
                                                    packet_info *pinfo, 
                                                    proto_tree *tree, 
                                                    zbee_nwk_green_power_packet *packet, 
                                                    guint offset)
{
  /* TODO: check it */
  proto_item   *ti = NULL;
  proto_tree   *field_tree = NULL;

  guint16      cluster_id = 0;

  (void)pinfo;
  (void)packet;

  /* Get Command Cluset Id and add value into tree */
  cluster_id = tvb_get_letohs(tvb, offset);
  if (tree) {
    proto_tree_add_uint(tree, hf_zbee_nwk_gp_cmd_attr_report_cluster_id, tvb, offset, sizeof(guint16), cluster_id);
  }
  offset += sizeof(guint16);
  
  /* Create subthree and parse ZCL Write Attribute Payload */
  if (tree) {
    guint ff = offset;
    ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint16), "Attribute reporting command for Cluster: 0x%02X", cluster_id);
    field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);
    dissect_zcl_attributes_payload(tvb, pinfo, field_tree, &ff);
    offset = ff;
  }

  return offset;
} /* dissect_zbee_nwk_gp_cmd_attr_reporting */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_channel_request
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_channel_request(tvbuff_t *tvb, 
                                                     packet_info *pinfo, 
                                                     proto_tree *tree, 
                                                     zbee_nwk_green_power_packet *packet, 
                                                     guint offset)
{
    proto_item                      *ti = NULL;
    proto_tree                      *field_tree = NULL;

    guint8                          tmp = 0;

    (void)pinfo;
    (void)packet;
    
    /* Get Command Options Field, build subtree and display results */
    tmp = tvb_get_guint8(tvb, offset);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Channel Toggling Behaviour: 0x%01x", tmp);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);
        
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_1st, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_1ST);
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_2nd, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_2ND);
    }
    offset += sizeof(guint8);

    return offset;
} /* dissect_zbee_nwk_gp_cmd_channel_request */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_channel_configuration
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_channel_configuration(tvbuff_t *tvb, 
                                                           packet_info *pinfo, 
                                                           proto_tree *tree, 
                                                           zbee_nwk_green_power_packet *packet, 
                                                           guint offset)
{
    proto_item                      *ti = NULL;
    proto_tree                      *field_tree = NULL;

    guint8                          tmp = 0;

    (void)pinfo;
    (void)packet;

    /* Get Command Options Field, build subtree and display results */
    tmp = tvb_get_guint8(tvb, offset);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Operational Channel: 0x%01x", tmp);
        field_tree = proto_item_add_subtree(ti, ett_zbee_nwk_cmd_options);
        
        proto_tree_add_uint(field_tree, hf_zbee_nwk_gp_cmd_channel_configuration, tvb, offset, sizeof(guint8), tmp & ZBEE_NWK_GP_CMD_CHANNEL_CONFIGURATION_OPERATION_CH);
    }
    offset += sizeof(guint8);

    return offset;
} /* dissect_zbee_nwk_gp_cmd_channel_configuration */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_move_up_down
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_move_up_down(tvbuff_t *tvb, 
                                                  packet_info *pinfo, 
                                                  proto_tree *tree, 
                                                  zbee_nwk_green_power_packet *packet, 
                                                  guint offset)
{
    guint8      tmp = 0;

    (void)pinfo;
    (void)packet;

    tmp = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Rate: %d", tmp);
    }
    offset += sizeof(guint8);

    return offset;
} /* dissect_zbee_nwk_gp_cmd_move_up_down */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_step_up_down
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_step_up_down(tvbuff_t *tvb, 
                                                  packet_info *pinfo, 
                                                  proto_tree *tree, 
                                                  zbee_nwk_green_power_packet *packet, 
                                                  guint offset)
{
    guint8      tmp1 = 0;
    guint16     tmp2 = 0;

    (void)pinfo;
    (void)packet;

    tmp1 = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Step Size: %d", tmp1);
    }
    offset += sizeof(guint8);

    tmp2 = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Transition Time: %d", tmp2);
    }
    offset += sizeof(guint16);

    return offset;
} /* dissect_zbee_nwk_gp_cmd_step_up_down */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_move_color
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_move_color(tvbuff_t *tvb, 
                                                packet_info *pinfo, 
                                                proto_tree *tree, 
                                                zbee_nwk_green_power_packet *packet, 
                                                guint offset)
{
    guint16     tmp = 0;

    (void)pinfo;
    (void)packet;

    tmp = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "RateX: %d", tmp);
    }
    offset += sizeof(guint16);

    tmp = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "RateY: %d", tmp);
    }
    offset += sizeof(guint16);

    return offset;
} /* dissect_zbee_nwk_gp_cmd_move_color */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_nwk_gp_cmd_step_color
 *  DESCRIPTION
 *      Dissector for Green Power Commands.
 *  PARAMETERS
 *      tvbuff_t *tvb                       - pointer to buffer containing raw packet.
 *      packet_into *pinfo                  - pointer to packet information fields.
 *      proto_tree *tree                    - pointer to data tree Wireshark uses to display packet.
 *      zbee_nwk_green_power_packet *packet - packet data. 
 *      guint offset                        - current payload offset.
 *  RETURNS
 *      guint                               - payload processed offset
 *---------------------------------------------------------------
 */

static guint dissect_zbee_nwk_gp_cmd_step_color(tvbuff_t *tvb, 
                                                packet_info *pinfo, 
                                                proto_tree *tree, 
                                                zbee_nwk_green_power_packet *packet, 
                                                guint offset)
{
    guint16     tmp = 0;

    (void)pinfo;
    (void)packet;

    tmp = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "StepX: %d", tmp);
    }
    offset += sizeof(guint16);

    tmp = tvb_get_letohs(tvb, offset);
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "StepY: %d", tmp);
    }
    offset += sizeof(guint16);

    /* optional time field */
    if (tvb->length - offset >= sizeof(guint16)) {
      tmp = tvb_get_letohs(tvb, offset);
      if (tree) {
        proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Transition time: %d", tmp);
      }
      offset += sizeof(guint16);
    }

    return offset;
} /* dissect_zbee_nwk_gp_cmd_step_color */

static void
gp_init_zbee_security(void)
{
    guint           i;
    key_record_t    key_record;

    if (zbee_gp_keyring) {
       g_slist_free(zbee_gp_keyring);
       zbee_gp_keyring = NULL;
    }
    for (i = 0; gp_uat_key_records && (i < num_uat_key_records); i++) {
        key_record.frame_num = 0;
        key_record.label = se_strdup(gp_uat_key_records[i].label);
        memcpy(&key_record.key, &gp_uat_key_records[i].key, ZBEE_SEC_CONST_KEYSIZE);
        zbee_gp_keyring = g_slist_prepend(zbee_gp_keyring, se_memdup(&key_record, sizeof(key_record_t)));
    }
}

static gboolean
zbee_gp_decrypt_payload(zbee_nwk_green_power_packet *packet, const gchar *enc_buffer, const gchar offset, guint8 *dec_buffer,
    guint payload_len, guint mic_len, guint8 *key)
{
    guint8 nonce[ZBEE_SEC_CONST_NONCE_LEN];
    guint8 buffer[ZBEE_SEC_CONST_BLOCKSIZE + 1];
    guint8 *key_buffer = key;

    zbee_gp_make_nonce(packet, nonce);

    if (zbee_sec_ccm_decrypt(key_buffer, nonce, enc_buffer, enc_buffer + offset, dec_buffer, offset, payload_len, mic_len)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static void
zbee_gp_make_nonce(zbee_nwk_green_power_packet *packet, gchar *nonce)
{
    memset(nonce, 0, ZBEE_SEC_CONST_NONCE_LEN);

    /* TODO: application_id == ZB_ZGP_APP_ID_0000 */
    /* TODO: application_id != ZB_ZGP_APP_ID_0000 */

    if (packet->direction == ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD) {
        nonce[0] = (guint8)((packet->source_id) & 0xff);
        nonce[1] = (guint8)((packet->source_id) >> 8 & 0xff);
        nonce[2] = (guint8)((packet->source_id) >> 16 & 0xff);
        nonce[3] = (guint8)((packet->source_id) >> 24 & 0xff);
    }
    nonce[4] = (guint8)((packet->source_id) & 0xff);
    nonce[5] = (guint8)((packet->source_id) >> 8 & 0xff);
    nonce[6] = (guint8)((packet->source_id) >> 16 & 0xff);
    nonce[7] = (guint8)((packet->source_id) >> 24 & 0xff);
    nonce[8] = (guint8)((packet->security_frame_counter) & 0xff);
    nonce[9] = (guint8)((packet->security_frame_counter) >> 8 & 0xff);
    nonce[10] = (guint8)((packet->security_frame_counter) >> 16 & 0xff);
    nonce[11] = (guint8)((packet->security_frame_counter) >> 24 & 0xff);
    if ((packet->application_id == ZBEE_NWK_GP_APP_ID_ZGP) && (packet->direction != ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD)) {
        nonce[12] = 0xa3;
    } else {
        nonce[12] = 0x05;
    }
}
