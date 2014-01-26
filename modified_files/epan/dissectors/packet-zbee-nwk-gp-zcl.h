#ifndef PACKET_ZBEE_NWK_GP_ZCL_H
#define PACKET_ZBEE_NWK_GP_ZCL_H

#include "packet-zbee-aps.h"

/* ClusterIDs Table From APS Sublayer this IDs (from APS header) 
 * and name table needed for correct parsing GP Attribute Request command
 */
extern const value_string zbee_aps_cid_names[];

/* See: A.4.2.3.1 Attribute reporting command
 * functio from ZCL dissector engine
 */
void dissect_zcl_attributes_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);

#endif /* PACKET_ZBEE_NWK_GP_ZCL_H */
