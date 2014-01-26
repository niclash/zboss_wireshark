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
PURPOSE: this plug-in allows to parse UBEC registers access over 802.15.
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

#define ZUZ_PORT 9998

static int proto_zuz = -1;
static gint ett_zuz = -1;
static gint ett_zuz_long_addr = -1;
static gint ett_zuz_short_addr = -1;
static gint ett_zuz_isrsts = -1;

static int hf_zuz_long_addr_short = -1;
static int hf_zuz_short_addr = -1;
static int hf_zuz_rw_short = -1;
static int hf_zuz_long_addr_long = -1;
static int hf_zuz_long_addr = -1;
static int hf_zuz_rw_long = -1;
static int hf_zuz_data = -1;
static int hf_zuz_frame_len = -1;
static int hf_zuz_fcs = -1;
static int hf_zuz_lqi = -1;
static int hf_zuz_rssi = -1;
static int hf_zuz_frame_timer = -1;
static int hf_zuz_superframe_counter = -1;
static int hf_zuz_w_header_len = -1;
static int hf_zuz_w_frame_len = -1;


static int hf_zuz_isrsts_slpif = -1;
static int hf_zuz_isrsts_wakeif = -1;
static int hf_zuz_isrsts_hsymtmrif = -1;
static int hf_zuz_isrsts_secif = -1;
static int hf_zuz_isrsts_rxif = -1;
static int hf_zuz_isrsts_txg2if = -1;
static int hf_zuz_isrsts_txg1if = -1;
static int hf_zuz_isrsts_txnif = -1;


#define ZUZ_LONG_ADDR_SHORT_MASK 0x80
#define ZUZ_SHORT_ADDR_MASK 0x7e
#define ZUZ_SHORT_RW_MASK 1

#define ZUZ_LONG_ADDR_LONG_MASK 0x8000
#define ZUZ_LONG_ADDR_MASK 0x7fe0
#define ZUZ_LONG_RW_MASK 0x10

#define ZUZ_ISRSTS_SLPIF_MASK      (1<<7)
#define ZUZ_ISRSTS_WAKEIF_MASK     (1<<6)
#define ZUZ_ISRSTS_HSYMTMRIF_MASK  (1<<5)
#define ZUZ_ISRSTS_SECIF_MASK      (1<<4)
#define ZUZ_ISRSTS_RXIF_MASK       (1<<3)
#define ZUZ_ISRSTS_TXG2IF_MASK     (1<<2)
#define ZUZ_ISRSTS_TXG1IF_MASK     (1<<1)
#define ZUZ_ISRSTS_TXNIF_MASK      (1<<0)



static dissector_handle_t ieee802154_handle;
static dissector_handle_t data_handle;
static conversation_t *conversation;
static dissector_handle_t zuz_handle;


enum fifo_kinds_e
{
  FIFO_RX,
  FIFO_GTS2,
  FIFO_GTS1,
  FIFO_BEACON,
  FIFO_TX,
  FIFO_TX_NORMAL_KEY,
  FIFO_TX_GTS1_KEY,
  FIFO_TX_GTS2_KEY,
  FIFO_RX_KEY
};


static const value_string zuz_fifo_kinds[] = {
  { FIFO_RX, "RX" },
  { FIFO_GTS2, "GTS2" },
  { FIFO_GTS1, "GTS1" },
  { FIFO_BEACON, "BEACON" },
  { FIFO_TX, "TX" },
  { FIFO_TX_NORMAL_KEY, "TX_NORMAL_KEY" },
  { FIFO_TX_GTS1_KEY, "TX_GTS1_KEY" },
  { FIFO_TX_GTS2_KEY, "TX_GTS2_KEY" },
  { FIFO_RX_KEY, "RX_KEY" },
  { 0, NULL }
};

static enum fifo_kinds_e get_fifo_kind(unsigned addr)
{

  if (addr >= 0x300 && addr <= 0x38f)
  {
    return FIFO_RX;
  }
  else if (addr >= 0x180 && addr <= 0x1ff)
  {
    return FIFO_GTS2;
  }
  else if (addr >= 0x100 && addr <= 0x17f)
  {
    return FIFO_GTS1;
  }
  else if (addr >= 0x80 && addr <= 0xff)
  {
    return FIFO_BEACON;
  }
  else if (/*addr >= 0x0 &&*/ addr <= 0x7f)
  {
    return FIFO_TX;
  }
  /* security FIFO */
  else if (addr >= 0x280 && addr <= 0x28f)
  {
    return FIFO_TX_NORMAL_KEY;
  }
  else if (addr >= 0x290 && addr <= 0x29f)
  {
    return FIFO_TX_GTS1_KEY;
  }
  else if (addr >= 0x2a0 && addr <= 0x2af)
  {
    return FIFO_TX_GTS2_KEY;
  }
  else if (addr >= 0x2b0 && addr <= 0x2bf)
  {
    return FIFO_RX_KEY;
  }
  return -1;
}


static void
dissect_zuz(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  unsigned char b;
  int is_long = 0;
  int is_write = -1;
  int is_out = 0;
  int is_fifo = 0;
  int is_fifo_rx = 0;
  unsigned addr = 0;
  tvbuff_t *payload_tvb;
  proto_item *ti = NULL;
  proto_tree *zuz_tree = NULL;

  /* get header type. Verify it and define i/o direction */
  b = tvb_get_guint8(tvb, 0);
  is_out = ((b & 0x80) != 0);

  /*
    Actions to parse:
    - short reg read
    - short reg write
    - long reg read
       - fifo read (detect fifo address)
         - parse packet - show and strip header, fcs, lqi, rssi, pass to wpan
    - long reg write
       - fifo write (detect fifo address)
         - parse packet, pass to wpan
   */

  /* See DS-2400-02_v1_3_RN.pdf 3.7.1 - SPI interface, 3.7.2 - I2C interface for examples */

  if (!is_out && tvb_reported_length(tvb) > 4)
  {
    /* When reading RX FIFO, has at least 1b length +2b fcs + 1b lqi + 1b rssi*/
    is_fifo_rx = TRUE;
  }
  else
  {
    b = tvb_get_guint8(tvb, 1);
    is_long = !!(b & (1<<7));
    b &= ~(1<<7);
    if (is_long)
    {
      addr = ((b << 8) | tvb_get_guint8(tvb, 2)) >> 4;
    }
    else
    {
      addr = b;
    }
    is_write = (addr & 1);
    addr >>= 1;
    is_fifo = (is_long && !(addr >= 0x200 && addr <= 0x2bf));
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
  {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZUZ");
  }

  if (check_col(pinfo->cinfo, COL_INFO))
  {
    if (is_fifo_rx)
    {
      /*  "fifo 0x123 R [10]" */
      col_add_fstr(pinfo->cinfo, COL_INFO, "fifo R [%d]",
                   tvb_get_guint8(tvb, 1));
    }
    else
    {
      /* string like:
         "S reg 0x23 W >data 0x234"
         "L reg 0x223 R >addr"
         "L reg 0x223 R <data 0x456"
         "fifo 0x123 W [10]"
      */
      if (is_write)
      {
        if (is_fifo)
        {
          col_add_fstr(pinfo->cinfo, COL_INFO, "fifo 0x%X W [%d]",
                       addr, tvb_reported_length(tvb) - 3);
        }
        else
        {
          col_add_fstr(pinfo->cinfo, COL_INFO, "%s reg 0x%X W >data 0x%x",
                       is_long ? "L" : "S",
                       addr,
                       tvb_get_guint8(tvb, 2 + is_long));
        }
      }
      else if (is_out)
      {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s 0x%X R >addr",
                     is_long ? "L" : "S",
                     is_fifo ? "fifo" : "reg",
                     addr);
      }
      else
      {
        /* there can't be fifo */
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s reg 0x%X R <data 0x%x",
                     is_long ? "L" : "S",
                     addr,
                     tvb_get_guint8(tvb, 2 + is_long));
      }
    }
  } /* if - cifo */

  if (tree)
  { /* we are being asked for details */
    ti = proto_tree_add_item(tree, proto_zuz, tvb, 0, -1, FALSE);
    zuz_tree = proto_item_add_subtree(ti, ett_zuz);


    proto_tree_add_text(zuz_tree, tvb, 0, sizeof(guint8), "Direction: %s.", is_write ? "outgoing" : "incoming");
    
    if (is_fifo_rx)
    {
      /* first byte - length */
      b = tvb_get_guint8(tvb, 1);

      proto_item_append_text(ti, ", fifo R [%d]", b);

      /* Frame length includes FCS but does not includes 9 bytes: LQI(1),
       * RSSI(1), Frame Timer(4), Superframe Counter (3)
       * See 3.2.3 RXMAC
       */
      proto_tree_add_item(zuz_tree, hf_zuz_frame_len, tvb, 1, 1, FALSE);

      /* [length] - data - do nothing now */

      /* There can be either read from rx fifo (got packet) or read from tx
       * fifo (reading result of encryption/decryption).
       * unfortunately, we have no context and can't check which fifo was read
       * from.
       * At real UZ2400 frame timer and superframe counter are zero when
       * receiving packet. Let's check for it.
       */

      if (tvb_get_ntohl(tvb, 2 + b + 2) == 0 /* hf_zuz_frame_timer */
          && tvb_get_ntoh24(tvb, 2 + b + 6) == 0 /* hf_zuz_superframe_counter */
        )
      {
        /* 2b FCS */
        proto_tree_add_item(zuz_tree, hf_zuz_fcs, tvb, 2 + b - 2, 2, FALSE);

        /* 1b LQI */
        proto_tree_add_item(zuz_tree, hf_zuz_lqi, tvb, 2 + b, 1, FALSE);

        /* 1b RSSI */
        proto_tree_add_item(zuz_tree, hf_zuz_rssi, tvb, 2 + b + 1, 1, FALSE);

        /* 4b Frame Timer */
        proto_tree_add_item(zuz_tree, hf_zuz_frame_timer, tvb, 2 + b + 2, 4, FALSE);

        /* 3b Superframe counter */
        proto_tree_add_item(zuz_tree, hf_zuz_superframe_counter, tvb, 2 + b + 6, 3, FALSE);

        /* pass to 802.15 */
        payload_tvb = tvb_new_subset(tvb, 2, b, b);
        TRY
        {
          /* if this is FIFO transfer, pass it to 802.15 dissector */
          call_dissector(ieee802154_handle, payload_tvb, pinfo, tree);
        }
        CATCH_ALL {
          show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
      }
      else
      {
        /* probably, this is read encryption result from TX fifo  */

        /* dump fifo contents */
        payload_tvb = tvb_new_subset(tvb, 2, -1, tvb_reported_length(tvb) - 2);
        TRY
        {
          /* FIFO transfer to be just dumped */
          call_dissector(data_handle, payload_tvb, pinfo, tree);
        }
        CATCH_ALL {
          show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
      }
    }    /* if parsing rx fifo data */
    else                        /* not fifo data rx */
    {
      if (is_fifo)
      {
        int fifo_kind = get_fifo_kind(addr);
        {
          proto_item *sub_ti
            = proto_tree_add_text(zuz_tree, tvb, 1, 2, "FIFO %x(%s) %s",
                                  addr,
                                  val_to_str(fifo_kind, zuz_fifo_kinds, "Unknown"),
                                  is_write ? "W" : "R");
          proto_tree *field_tree = proto_item_add_subtree(sub_ti, ett_zuz_long_addr);
          unsigned w = tvb_get_ntohs(tvb, 1);

          proto_item_append_text(ti, ", FIFO %x(%s) %s",
                                 addr,
                                 val_to_str(fifo_kind, zuz_fifo_kinds, "Unknown"),
                                 is_write ? "W" : "R");
          if (is_write)
          {
            proto_item_append_text(ti, " [%d]", tvb_reported_length(tvb) - 3);
          }

          /* show long fifo address (2b) */
          proto_tree_add_boolean(field_tree, hf_zuz_long_addr_long, tvb, 1, 2, w & ZUZ_LONG_ADDR_LONG_MASK);
          proto_tree_add_uint(field_tree, hf_zuz_long_addr, tvb, 1, 2, w & ZUZ_LONG_ADDR_MASK);
          proto_tree_add_boolean(field_tree, hf_zuz_rw_long, tvb, 1, 2, w & ZUZ_LONG_RW_MASK);
        }
        if (is_write
            && tvb_reported_length(tvb) > 4)
        {
          /* FIFO write has following fields: hdr len, frame len, header, frame
             See 4.3.1
           */
          proto_tree_add_item(zuz_tree, hf_zuz_w_header_len, tvb, 3, 1, FALSE);
          proto_tree_add_item(zuz_tree, hf_zuz_w_frame_len, tvb, 4, 1, FALSE);

          /* have data in this packet */
          if (fifo_kind == FIFO_GTS2
              || fifo_kind == FIFO_GTS1
              || fifo_kind == FIFO_BEACON
              || (fifo_kind == FIFO_TX && tvb_get_guint8(tvb, 3) < 20))
          {
            /* pass to 802.15 */
            payload_tvb = tvb_new_subset(tvb, 5, -1, tvb_reported_length(tvb) - 5);
            TRY
            {
              /* if this is FIFO transfer, pass it to 802.15 dissector */
              call_dissector(ieee802154_handle, payload_tvb, pinfo, tree);
            }
            CATCH_ALL {
              show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            }
            ENDTRY;
          } /* if fifo to pass to 802.15 */
          else
          {
            /* dump fifo contents */
            payload_tvb = tvb_new_subset(tvb, 5, -1, tvb_reported_length(tvb) - 5);
            TRY
            {
              /* FIFO transfer to be just dumped */
              call_dissector(data_handle, payload_tvb, pinfo, tree);
            }
            CATCH_ALL {
              show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            }
            ENDTRY;
          }
        }
        else if (tvb_reported_length(tvb) > 3)
        {
          /* some strange extra bytes! TODO: mark it somehow (how?) */
          payload_tvb = tvb_new_subset(tvb, 3, -1, tvb_reported_length(tvb) - 5);
          TRY
          {
            /* FIFO transfer to be just dumped */
            call_dissector(data_handle, payload_tvb, pinfo, tree);
          }
          CATCH_ALL {
            show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
          }
          ENDTRY;
        }
      }
      else                      /* not fifo - reg write or reg rx addr */
      {
        /* show control reg address (1b short, 2b long) */
        if (is_long)
        {
          /* dissect long addr */
          proto_item *sub_ti
            = proto_tree_add_text(zuz_tree, tvb, 1, sizeof(guint16), "L reg 0x%x %s",
                                  addr, is_write ? "W" : "R");
          proto_tree *field_tree = proto_item_add_subtree(sub_ti, ett_zuz_long_addr);
          unsigned w = tvb_get_ntohs(tvb, 1);

          if (is_write)
          {
            proto_item_append_text(ti, ", L reg 0x%x W data 0x%x",
                                   addr, tvb_get_guint8(tvb, 3));
          }
          else
          {
            proto_item_append_text(ti, ", L reg 0x%x R %s", addr, (is_out ? ">addr" : "(fake 2 addr bytes!) <data"));
            if (!is_out)
            {
              proto_item_append_text(ti, " 0x%x", tvb_get_guint8(tvb, 3));
            }
          }

          /* show long fifo address (2b) */
          proto_tree_add_boolean(field_tree, hf_zuz_long_addr_long, tvb, 1, 2, w & ZUZ_LONG_ADDR_LONG_MASK);
          proto_tree_add_uint(field_tree, hf_zuz_long_addr, tvb, 1, 2, w & ZUZ_LONG_ADDR_MASK);
          proto_tree_add_boolean(field_tree, hf_zuz_rw_long, tvb, 1, 2, w & ZUZ_LONG_RW_MASK);
        }
        else
        {
          /* dissect short addr */
          proto_item *sub_ti
            = proto_tree_add_text(zuz_tree, tvb, 1, 1, "S reg 0x%x %s",
                                  addr, is_write ? "W" : (is_out ? "R >addr" : "(fake addr byte!) R <data"));
          proto_tree *field_tree = proto_item_add_subtree(sub_ti, ett_zuz_short_addr);
          unsigned w = tvb_get_guint8(tvb, 1);

          if (is_write)
          {
            proto_item_append_text(ti, ", S reg 0x%x W data 0x%x",
                                   addr, tvb_get_guint8(tvb, 2));
          }
          else
          {
            proto_item_append_text(ti, ", S reg 0x%x R %s", addr, (is_out ? ">addr" : "<data"));
            if (!is_out)
            {
              proto_item_append_text(ti, " 0x%x", tvb_get_guint8(tvb, 2));
            }
          }

          /* show short fifo address (1b) */
          proto_tree_add_boolean(field_tree, hf_zuz_long_addr_short, tvb, 1, 1, w & ZUZ_LONG_ADDR_SHORT_MASK);
          proto_tree_add_uint(field_tree, hf_zuz_short_addr, tvb, 1, 1, w & ZUZ_SHORT_ADDR_MASK);
          proto_tree_add_boolean(field_tree, hf_zuz_rw_short, tvb, 1, 1, w & ZUZ_SHORT_RW_MASK);
        }

        if (is_write || !is_out)
        {
          /* show data byte. Additionally parse some regs */
          switch (addr)
          {
            case 0x31:          /* interrupt status */
            {
              unsigned w = tvb_get_guint8(tvb, 2 + is_long);
              proto_item *sub_ti = proto_tree_add_text(zuz_tree, tvb, 2 + is_long, 1, "ISRSTS 0x%x", w);
              proto_tree *field_tree = proto_item_add_subtree(sub_ti, ett_zuz_isrsts);

              proto_item_append_text(ti, ", ISRSTS 0x%x", w);

              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_slpif, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_SLPIF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_wakeif, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_WAKEIF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_hsymtmrif, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_HSYMTMRIF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_secif, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_SECIF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_rxif, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_RXIF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_txg2if, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_TXG2IF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_txg1if, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_TXG1IF_MASK);
              proto_tree_add_boolean(field_tree, hf_zuz_isrsts_txnif, tvb, 2 + is_long, 1, w & ZUZ_ISRSTS_TXNIF_MASK);
            }
            break;
            /* TODO: parse more registers */
            default:
              proto_tree_add_item(zuz_tree, hf_zuz_data, tvb, 2 + is_long, 1, FALSE);
              break;
          }
        }
      } /* else - not fifo */
    }   /* else - not fifo rx */
       }     /* if tree */
}

static gboolean
dissect_zuz_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if ( tvb_get_guint8(tvb, 0) != 0x81 )
    {
        return (FALSE);
    }
    if ( tvb_get_guint8(tvb, 0) != 0x01 )
    {
        return (FALSE);
    }
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, zuz_handle);
    dissect_zuz(tvb, pinfo, tree);
    return (TRUE);
}

void
proto_register_zuz(void)
{
  static hf_register_info hf[] = {
    /* short reg :

       7 6 5 4 3 2 1 0
       | \________/  \_ r/w flag
       |  short address
       long flag
    */

    { &hf_zuz_long_addr_short,
      { "Long address", "zuz.long_address_short", FT_BOOLEAN, 8, NULL, ZUZ_LONG_ADDR_SHORT_MASK, "Long address flag (0)", HFILL}},

    { &hf_zuz_short_addr,
      { "Reg address", "zuz.short_address", FT_UINT8, BASE_HEX, NULL, ZUZ_SHORT_ADDR_MASK, "Short address body", HFILL}},

    { &hf_zuz_rw_short,
      { "Read/Write", "zuz.short_rw", FT_BOOLEAN, 8, NULL, ZUZ_SHORT_RW_MASK, "W flag", HFILL}},

    /* long reg:

       7 6 5 4 3 2 1 0  7 6 5 4 3 2 1 0
       | \____________  ____/ \_ r/w flag
       |     long address
       long flag
    */

    { &hf_zuz_long_addr_long,
      { "Long address", "zuz.long_address_long", FT_BOOLEAN, 16, NULL, ZUZ_LONG_ADDR_LONG_MASK, "Long address flag (1)", HFILL}},

    { &hf_zuz_long_addr,
      { "Reg address", "zuz.long_address", FT_UINT16, BASE_HEX, NULL, ZUZ_LONG_ADDR_MASK, "Long address body", HFILL}},

    { &hf_zuz_rw_long,
      { "Read/Write", "zuz.long_rw", FT_BOOLEAN, 16, NULL, ZUZ_LONG_RW_MASK, "W flag", HFILL}},

    /* data following reg address */

    { &hf_zuz_data,
      { "Data", "zuz.data", FT_UINT8, BASE_HEX, NULL, 0x0, "Reg data", HFILL}},

    /* Rx FIFO contents: len(1), data[len], FCS(2), LQI(1), RSSI(1) */

    { &hf_zuz_frame_len,
			{ "Frame length", "zuz.frame_len", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Frame payload length in RX FIFO, not including FCS, LQI, RSSI", HFILL }},

    { &hf_zuz_fcs,
			{ "FCS", "zuz.fcs", FT_UINT16, BASE_HEX, NULL, 0x0, "RX frame FCS", HFILL }},

    { &hf_zuz_lqi,
			{ "LQI", "zuz.lqi", FT_UINT8, BASE_HEX, NULL, 0x0, "RX frame LQI", HFILL }},

    { &hf_zuz_rssi,
			{ "RSSI", "zuz.rssi", FT_UINT8, BASE_HEX, NULL, 0x0, "RX frame RSSI", HFILL }},

    { &hf_zuz_frame_timer,
			{ "Frame timer", "zuz.frame_timer", FT_UINT32, BASE_HEX, NULL, 0x0, "RX frame timer", HFILL }},

    { &hf_zuz_superframe_counter,
			{ "Superframe counter", "zuz.superframe_counter", FT_UINT24, BASE_HEX, NULL, 0x0, "RX superframe counter", HFILL }},


    { &hf_zuz_w_header_len,
			{ "Header length", "zuz.w_header_len", FT_UINT8, BASE_DEC, NULL, 0x0, "W header length", HFILL }},

    { &hf_zuz_w_frame_len,
			{ "Frame length", "zuz.w_frame_len", FT_UINT8, BASE_DEC, NULL, 0x0, "W frame length", HFILL }},


    /* Some registers */

    /* Interrupt status - ISRSTS */
    { &hf_zuz_isrsts_slpif,
      { "SLPIF", "zuz.isrsts_slpif", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_SLPIF_MASK, "Sleep alert interrupt", HFILL}},
    { &hf_zuz_isrsts_wakeif,
      { "WAKEIF", "zuz.isrsts_wakeif", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_WAKEIF_MASK, "Wake-up alert interrupt", HFILL}},
    { &hf_zuz_isrsts_hsymtmrif,
      { "HSYMTMRIF", "zuz.isrsts_hsymtmrif", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_HSYMTMRIF_MASK, "Half symbol timer interrupt", HFILL}},
    { &hf_zuz_isrsts_secif,
      { "SECIF", "zuz.isrsts_secif", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_SECIF_MASK, "Security key request interrupt", HFILL}},
    { &hf_zuz_isrsts_rxif,
      { "RXIF", "zuz.isrsts_rxif", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_RXIF_MASK, "RX receive interrupt", HFILL}},
    { &hf_zuz_isrsts_txg2if,
      { "TXG2IF", "zuz.isrsts_txg2if", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_TXG2IF_MASK, "TX GTS2 FIFI transmission interrupt", HFILL}},
    { &hf_zuz_isrsts_txg1if,
      { "TXG1IF", "zuz.isrsts_txg1if", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_TXG1IF_MASK, "TX GTS1 FIFI transmission interrupt", HFILL}},
    { &hf_zuz_isrsts_txnif,
      { "TXNIF", "zuz.isrsts_txnif", FT_BOOLEAN, 8, NULL, ZUZ_ISRSTS_TXNIF_MASK, "TX Normal FIFO transmission interrupt", HFILL}}


  };

	/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_zuz,
    &ett_zuz_long_addr,
    &ett_zuz_short_addr,
    &ett_zuz_isrsts
  };

  proto_zuz = proto_register_protocol (
    "ZigBee UZ24x0 regs",	/* name */
    "ZUZ",		/* short name */
    "zuz"		/* abbrev     */
    );

  proto_register_field_array(proto_zuz, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_zuz(void)
{
  static gboolean inited = FALSE;

  if (!inited)
  {
    ieee802154_handle = find_dissector("wpan");
    data_handle = find_dissector("data");
    zuz_handle = create_dissector_handle(dissect_zuz, proto_zuz);
    inited = TRUE;
  }
  else
  {
    dissector_delete_uint("udp.port", ZUZ_PORT, zuz_handle);
  }
  dissector_add_uint("udp.port", ZUZ_PORT, zuz_handle);
//  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4, zuz_handle);
//  heur_dissector_add("wpan", dissect_zuz_heur, proto_zuz);
}
