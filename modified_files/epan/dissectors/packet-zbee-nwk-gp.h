#ifndef PACKET_ZBEE_NWK_GP_H
#define PACKET_ZBEE_NWK_GP_H

/* ################################################################################### */

/*  ZigBee NWK GP FCF Frame Types */
#define ZBEE_NWK_GP_FCF_DATA                  0x00
#define ZBEE_NWK_GP_FCF_MAINTENANCE           0x01

/*  ZigBee NWK GP FCF fields */
#define ZBEE_NWK_GP_FCF_FRAME_TYPE            0x03
#define ZBEE_NWK_GP_FCF_VERSION               0x3C
#define ZBEE_NWK_GP_FCF_AUTO_COMMISSIONING    0x40
#define ZBEE_NWK_GP_FCF_CONTROL_EXTENSION     0x80

/* Extended NWK Frame Control field */
#define ZBEE_NWK_GP_FCF_EXT_APP_ID            0x07  /* 0-2b */
#define ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL    0x18  /* 3-4b */
#define ZBEE_NWK_GP_FCF_EXT_SECURITY_KEY      0x20  /* 5b */
#define ZBEE_NWK_GP_FCF_EXT_RX_AFTER_TX       0x40  /* 6b */
#define ZBEE_NWK_GP_FCF_EXT_DIRECTION         0x80  /* 7b */

/* Definitions for application ids */
#define ZBEE_NWK_GP_APP_ID_DEFAULT            0x00
#define ZBEE_NWK_GP_APP_ID_ZGP                0x02
#define ZBEE_NWK_GP_APP_ID_LPED               0x01

/* Definitions for GP Directions */
#define ZBEE_NWK_GP_FC_EXT_DIRECTION_DEFAULT      0x00
#define ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD    0x00
#define ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPP    0x01

/* Definitions for ZGPD Source Id */
#define ZBEE_NWK_GP_ZGPD_SRCID_UNKNOWN        0x00000000
#define ZBEE_NWK_GP_ZGPD_SRCID_ALL            0xFFFFFFFF

/* Security level values */
#define ZBEE_NWK_GP_SECURITY_LEVEL_NO         0x00 /* No security */
#define ZBEE_NWK_GP_SECURITY_LEVEL_1LSB       0x01 /* 1LSB of frame counter and short (2B) MIC only */
#define ZBEE_NWK_GP_SECURITY_LEVEL_FULL       0x02 /* Full (4B) frame counter and full (4B) MIC only */
#define ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR   0x03 /* Encryption & full (4B) frame counter and full (4B) MIC */

/* GP Security Key Type */
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_NO_KEY                              0x00
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_ZB_NWK_KEY                          0x01
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_GPD_GROUP_KEY                       0x02
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_NWK_KEY_DERIVED_GPD_KEY_GROUP_KEY   0x03
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_PRECONFIGURED_INDIVIDUAL_GPD_KEY    0x04
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_DERIVED_INDIVIDUAL_GPD_KEY          0x07

/* ################################################################################### */

typedef struct {
  /* FCF Data */  
  guint8      frame_type;
  guint8      protocol_version;
  gboolean    auto_commissioning;
  gboolean    nwk_frame_control_extension;

  /* Ext FCF Data */
  guint8      application_id;
  guint8      security_level;
  gboolean    security_key_present;
  gboolean    rx_after_tx;
  guint8      direction;

  /* Src Id */
  guint32     source_id;

  /* Security Frame Counter */
  guint32     security_frame_counter;
  
  /* MIC (0-2-4B) */
  guint8      mic_size;
  guint32     mic;

  /* Application Payload */
  guint8      payload_offset;
  guint8      payload_len;

  /* GP NWK Command Id */
  guint8      command_id;

  /* GPD Cmd paylod structure */
  void        *cmd_payload_structure;
} zbee_nwk_green_power_packet;

/* ################################################################################### */
/* ################################################################################### */

/* Commissioning Data Structure */
/* See: Figure 72 – Format of the Options field of the Commissioning command */
typedef struct {
  gboolean    mac_seq_num_capability;
  gboolean    rx_on_capability;
  gboolean    pan_id_request;
  gboolean    gp_sec_key_request;
  gboolean    fixed_location;
  gboolean    extended_options;
  gboolean    manufacturer_data_present; /* See: 13-0146-01 ZigBee GP Document, Manufacturer Specific device */
} zbee_nwk_gp_cmd_commissioning_options_t;

/* See: Figure 73 – Format of the Extended Options field of the Commissioning command */
typedef struct {
  gboolean    sec_level_capabilities;
  gboolean    key_type;
  gboolean    gpd_key_present;
  gboolean    gpd_key_encryption;
  gboolean    gpd_outgoing_counter_present;
} zbee_nwk_gp_cmd_commissioning_options_extended_t;

/* Figure 71 – Format of the Commissioning command payload */
typedef struct {
  /* Device Id */
  guint8                                            device_id;
  /* Options */
  zbee_nwk_gp_cmd_commissioning_options_t           options;
  /* Extended options */
  zbee_nwk_gp_cmd_commissioning_options_extended_t  extended_options;
  /* Security Key */
  guint8                                            security_key[16];
  /* GPD Key MIC */
  guint32                                           gpd_key_mic;
  /* GPD Outgoing Counter */
  guint32                                           gpd_outgoing_counter;
  /* Manufacturer ID */
  guint16                                           manufacturer_id;
  /* Manufacturer Device ID */
  guint8                                            manufacturer_device_id;
} zbee_nwk_gp_cmd_commissioning_t;

/* Definitions for GP Commissioning command OPTION field (bitmask) */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MAC_SEQ           0x01 /* 0b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_RX_ON_CAP         0x02 /* 1b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MANUFACTURER_INFO 0x04 /* 3b */ /* Reserved bit, is used as manufacturer info flag */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_PAN_ID_REQ        0x10 /* 4b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_GP_SEC_KEY_REQ    0x20 /* 5b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_FIXED_LOCATION    0x40 /* 6b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS       0x80 /* 7b */

/* Definitions for GP Commissioning command EXTENDED OPTION field (bitmask) */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_SEC_LEVEL_CAP    0x03 /* 0-1b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_KEY_TYPE         0x1C /* 2-4b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT  0x20 /* 5b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR     0x40 /* 6b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNETR      0x80 /* 7b */

/* ################################################################################### */

/* Commissioning Replay Data Structure */
/* See: Figure 75 – Format of the Options field of the Decommissioning command */
typedef struct {
  gboolean    panid_present;
  gboolean    sec_key_present;
  gboolean    sec_key_ecryption;
  guint8      security_level;
  guint8      key_type;
} zbee_nwk_gp_cmd_commissioning_reply_options_t;

/* Figure 74 – Format of the Commissioning Replay command payload */
typedef struct {
  zbee_nwk_gp_cmd_commissioning_reply_options_t options;
  guint16                                       pan_id;
  guint8                                        security_key[16];
  guint32                                       gpd_key_mic;
} zbee_nwk_gp_cmd_commissioning_replay_t;

/* Definitions for GP Decommissioning command OPTION field (bitmask) */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT    0x01 /* 0b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT   0x02 /* 1b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR          0x04 /* 2b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL         0x18 /* 3-4b */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_TYPE          0xE0 /* 5-7b */

/* ################################################################################### */
/* ################################################################################### */
/* ################################################################################### */

/* Definitions for GP Channel Request command */
#define ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_1ST    0x0F /* 0-3b */
#define ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_2ND    0xF0 /* 4-7b */

/* Definitions for GP Channel Configuration command */
#define ZBEE_NWK_GP_CMD_CHANNEL_CONFIGURATION_OPERATION_CH    0x0F /* 0-3b */

/* ################################################################################### */
/* ################################################################################### */
/* ################################################################################### */
/* GPD Device IDs */

/* GP GENERIC */
#define GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_1STATE_SWITCH     0x00
#define GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_2STATE_SWITCH     0x01
#define GPD_DEVICE_ID_GENERIC_GP_ON_OFF_SWITCH                    0x02
#define GPD_DEVICE_ID_GENERIC_GP_LEVEL_CONTROL_SWITCH             0x03
#define GPD_DEVICE_ID_GENERIC_GP_SIMPLE_SENSOR                    0x04
#define GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_1STATE_SWITCH   0x05
#define GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_2STATE_SWITCH   0x06
/* GP LIGHTING */
#define GPD_DEVICE_ID_LIGHTING_GP_COLOR_DIMMER_SWITCH             0x10
#define GPD_DEVICE_ID_LIGHTING_GP_LIGHT_SENSOR                    0x11
#define GPD_DEVICE_ID_LIGHTING_GP_OCCUPANCY_SENSOR                0x12
/* GP CLOSURES */
#define GPD_DEVICE_ID_CLOSURES_GP_DOOR_LOCK_CONTROLLER            0x20
/* HVAC */
#define GPD_DEVICE_ID_HVAC_GP_TEMPERATURE_SENSOR                  0x30
#define GPD_DEVICE_ID_HVAC_GP_PRESSURE_SENSOR                     0x31
#define GPD_DEVICE_ID_HVAC_GP_FLOW_SENSOR                         0x32
#define GPD_DEVICE_ID_HVAC_GP_INDOOR_ENVIRONMENT_SENSOR           0x33
/* Manufacturer specific device */
#define GPD_DEVICE_ID_MANUFACTURER_SPECIFIC                       0xFE

/* ################################################################################### */

/* GP Commands Ids */
/* Table 47 – Payloadless GPDF commands sent by GPD */
#define ZB_GP_CMD_ID_IDENTIFY             0x00
#define ZB_GP_CMD_ID_SCENE0               0x10
#define ZB_GP_CMD_ID_SCENE1               0x11
#define ZB_GP_CMD_ID_SCENE2               0x12
#define ZB_GP_CMD_ID_SCENE3               0x13
#define ZB_GP_CMD_ID_SCENE4               0x14
#define ZB_GP_CMD_ID_SCENE5               0x15
#define ZB_GP_CMD_ID_SCENE6               0x16
#define ZB_GP_CMD_ID_SCENE7               0x17
#define ZB_GP_CMD_ID_SCENE8               0x18
#define ZB_GP_CMD_ID_SCENE9               0x19
#define ZB_GP_CMD_ID_SCENE10              0x1A
#define ZB_GP_CMD_ID_SCENE11              0x1B
#define ZB_GP_CMD_ID_SCENE12              0x1C
#define ZB_GP_CMD_ID_SCENE13              0x1D
#define ZB_GP_CMD_ID_SCENE14              0x1E
#define ZB_GP_CMD_ID_SCENE15              0x1F
#define ZB_GP_CMD_ID_OFF                  0x20
#define ZB_GP_CMD_ID_ON                   0x21
#define ZB_GP_CMD_ID_TOGGLE               0x22
#define ZB_GP_CMD_ID_RELEASE              0x23
#define ZB_GP_CMD_ID_LEVEL_CONTROL_STOP   0x34
#define ZB_GP_CMD_ID_MOVE_HUE_STOP        0x40
#define ZB_GP_CMD_ID_MOVE_SATURATION_STOP 0x45
#define ZB_GP_CMD_ID_LOCK_DOOR            0x50
#define ZB_GP_CMD_ID_UNLOCK_DOOR          0x51
#define ZB_GP_CMD_ID_PRESS11              0x60
#define ZB_GP_CMD_ID_RELEASE11            0x61
#define ZB_GP_CMD_ID_PRESS12              0x62
#define ZB_GP_CMD_ID_RELEASE12            0x63
#define ZB_GP_CMD_ID_PRESS22              0x64
#define ZB_GP_CMD_ID_RELEASE22            0x65
#define ZB_GP_CMD_ID_SHORT_PRESS11        0x66
#define ZB_GP_CMD_ID_SHORT_PRESS12        0x67
#define ZB_GP_CMD_ID_SHORT_PRESS22        0x68
#define ZB_GP_CMD_ID_DECOMMISSIONING      0xE1
#define ZB_GP_CMD_ID_SUCCESS              0xE2

/* Table 48 – GPDF commands with payload sent by GPD */
#define ZB_GP_CMD_ID_MOVE_UP                                  0x30
#define ZB_GP_CMD_ID_MOVE_DOWN                                0x31
#define ZB_GP_CMD_ID_STEP_UP                                  0x32
#define ZB_GP_CMD_ID_STEP_DOWN                                0x33
#define ZB_GP_CMD_ID_MOVE_UP_WITH_ON_OFF                      0x35
#define ZB_GP_CMD_ID_MOVE_DOWN_WITH_ON_OFF                    0x36
#define ZB_GP_CMD_ID_STEP_UP_WITH_ON_OFF                      0x37
#define ZB_GP_CMD_ID_STEP_DOWN_WITH_ON_OFF                    0x38
#define ZB_GP_CMD_ID_MOVE_HUE_UP                              0x41
#define ZB_GP_CMD_ID_MOVE_HUE_DOWN                            0x42
#define ZB_GP_CMD_ID_STEP_HUE_UP                              0x43
#define ZB_GP_CMD_ID_STEP_HUW_DOWN                            0x44
#define ZB_GP_CMD_ID_MOVE_SATUREATION_UP                      0x46
#define ZB_GP_CMD_ID_MOVE_SATUREATION_DOWN                    0x47
#define ZB_GP_CMD_ID_STEP_SATURATION_UP                       0x48
#define ZB_GP_CMD_ID_STEP_SATURATION_DOWN                     0x49
#define ZB_GP_CMD_ID_MOVE_COLOR                               0x4A
#define ZB_GP_CMD_ID_STEP_COLOR                               0x4B
#define ZB_GP_CMD_ID_ATTRIBUTE_REPORTING                      0xA0
#define ZB_GP_CMD_ID_MANUFACTURE_SPECIFIC_ATTR_REPORTING      0xA1
#define ZB_GP_CMD_ID_MULTI_CLUSTER_REPORTING                  0xA2
#define ZB_GP_CMD_ID_MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING 0xA3
#define ZB_GP_CMD_ID_REQUEST_ATTRIBUTES                       0xA4
#define ZB_GP_CMD_ID_READ_ATTRIBUTES_RESPONSE                 0xA5
#define ZB_GP_CMD_ID_ANY_SENSOR_COMMAND_A0_A3                 0xAF
#define ZB_GP_CMD_ID_COMMISSIONING                            0xE0
#define ZB_GP_CMD_ID_CHANNEL_REQUEST                          0xE3

/* Table 49 – GPDF commands sent to GPD */
#define ZB_GP_CMD_ID_COMMISSIONING_REPLY      0xF0
#define ZB_GP_CMD_ID_WRITE_ATTRIBUTES         0xF1
#define ZB_GP_CMD_ID_READ_ATTRIBUTES          0xF2
#define ZB_GP_CMD_ID_CHANNEL_CONFIGURATION    0xF3

#endif /* PACKET_ZBEE_NWK_GP_H */
