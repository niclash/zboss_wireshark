/***************************************************************************
*                      ZBOSS ZigBee Pro 2007 stack                         *
*                                                                          *
*          Copyright (c) 2012 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*                            All rights reserved.                          *
*          Copyright (c) 2011 ClarIDy Solutions, Inc., Taipei, Taiwan.     *
*                       http://www.claridy.com/                            *
*                                                                          *
*          Copyright (c) 2011 Uniband Electronic Corporation (UBEC),       *
*                             Hsinchu, Taiwan.                             *
*                       http://www.ubec.com.tw/                            *
*                                                                          *
*          Copyright (c) 2011 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*                            All rights reserved.                          *
*                                                                          *
*                                                                          *
* ZigBee Pro 2007 stack, also known as ZBOSS (R) ZB stack is available     *
* under either the terms of the Commercial License or the GNU General      *
* Public License version 2.0.  As a recipient of ZigBee Pro 2007 stack, you*
* may choose which license to receive this code under (except as noted in  *
* per-module LICENSE files).                                               *
*                                                                          *
* ZBOSS is a registered trademark of DSR Corporation AKA Data Storage      *
* Research LLC.                                                            *
*                                                                          *
* GNU General Public License Usage                                         *
* This file may be used under the terms of the GNU General Public License  *
* version 2.0 as published by the Free Software Foundation and appearing   *
* in the file LICENSE.GPL included in the packaging of this file.  Please  *
* review the following information to ensure the GNU General Public        *
* License version 2.0 requirements will be met:                            *
* http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.                   *
*                                                                          *
* Commercial Usage                                                         *
* Licensees holding valid ClarIDy/UBEC/DSR Commercial licenses may use     *
* this file in accordance with the ClarIDy/UBEC/DSR Commercial License     *
* Agreement provided with the Software or, alternatively, in accordance    *
* with the terms contained in a written agreement between you and          *
* ClarIDy/UBEC/DSR.                                                        *
*                                                                          *
****************************************************************************
PURPOSE: ZigBee over UDP.
*/

#ifndef _MSC_VER
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#else
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/dissectors/packet-frame.h>

#define ZUDP_PORT 9999

static int proto_zudp = -1;
static int hf_zudp_packet_size = -1;
static gint ett_zudp = -1;

static dissector_handle_t ieee802154_handle;

static void
dissect_zudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *volatile payload_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZUDP");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) { /* we are being asked for details */
    proto_item *ti = NULL;
    proto_tree *zudp_tree = NULL;

    ti = proto_tree_add_item(tree, proto_zudp, tvb, 0, -1, FALSE);
    zudp_tree = proto_item_add_subtree(ti, ett_zudp);
    proto_tree_add_item(zudp_tree, hf_zudp_packet_size, tvb, 0, 1, FALSE);

    TRY
    {
      payload_tvb = tvb_new_subset(tvb, 1, -1, tvb_reported_length(tvb) - 1);
      call_dissector(ieee802154_handle, payload_tvb, pinfo, tree);
    }
    CATCH_ALL {
      show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
    }
    ENDTRY;
	}
}

void
proto_register_zudp(void)
{
  static hf_register_info hf[] = {
    { &hf_zudp_packet_size,
			{ "ZUDP packet size", "zudp.packet.size",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_zudp
  };

  proto_zudp = proto_register_protocol (
    "ZigBee over UDP",	/* name       */
    "ZUDP",		/* short name */
    "zudp"		/* abbrev     */
    );

  proto_register_field_array(proto_zudp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_zudp(void)
{
  static dissector_handle_t zudp_handle;

  ieee802154_handle = find_dissector("wpan");

  zudp_handle = create_dissector_handle(dissect_zudp, proto_zudp);
  dissector_add_uint("udp.port", ZUDP_PORT, zudp_handle);
}

