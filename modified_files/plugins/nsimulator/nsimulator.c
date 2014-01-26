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
PURPOSE: direction detector for ZigBee network simulator.
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
#include <epan/conversation.h>
#include <epan/dissectors/packet-ieee802154.h>

static dissector_handle_t wpan_handle = -1;
static dissector_handle_t data_handle = -1;
static dissector_handle_t nsimulator_handle = -1;
static gint ett_nsimulator = -1;
static int proto_nsimulator = -1;
static conversation_t *conversation;

static void
dissect_nsimulator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 b;
  guint32 signature;
  tvbuff_t *payload_tvb;
  proto_item *ns_tree = NULL;
  proto_item *ns_subtree = NULL;

  if (tvb_length(tvb) > 4) {
    b = tvb_get_guint8(tvb, 0);
    signature = tvb_get_letohl(tvb, 0);
    if ( signature == 0xFF77DE02 || signature == 0xFF77DE82 )
    {
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
      {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Network Simulator");
      }
      if (tree)
      {
        ns_tree = proto_tree_add_item(tree, proto_nsimulator, tvb, 0,
          sizeof(guint8), FALSE);
        ns_subtree = proto_item_add_subtree(ns_tree, ett_nsimulator);
        proto_tree_add_text(ns_subtree, tvb, 0, sizeof(guint8),
          "Direction is %s", b == 0x02 ? "incoming" : "outgoing");
        proto_tree_add_text(ns_subtree, tvb, 1, 3 * sizeof(guint8),
          "Network simulator additional signature");
      }
      payload_tvb = tvb_new_subset(tvb, 4, -1, tvb_reported_length(tvb) - 4);
      TRY
      {
        call_dissector(wpan_handle, payload_tvb, pinfo, tree);
      }
      CATCH_ALL {
        show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
      }
      ENDTRY;
    } else {
      TRY
      {
        call_dissector(wpan_handle, tvb, pinfo, tree);
      }
      CATCH_ALL {
        show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
      }
      ENDTRY;
    }
  } else {
    TRY
    {
      call_dissector(wpan_handle, tvb, pinfo, tree);
    }
    CATCH_ALL {
      show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
    }
    ENDTRY;
  }
}

void
proto_register_nsimulator(void)
{
  static gint *ett[] = {
    &ett_nsimulator
  };

  proto_nsimulator = proto_register_protocol (
    "ZBOSS Network Simulator Detector",
    "ZBOSS NS",
    "nsimulator"
  );
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nsimulator(void)
{
  static gboolean inited = FALSE;

  if (!inited)
  {
    wpan_handle = find_dissector("wpan");
    data_handle = find_dissector("data");
    nsimulator_handle = create_dissector_handle(dissect_nsimulator,
      proto_nsimulator);
    inited = TRUE;
  }
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4, nsimulator_handle);
}
