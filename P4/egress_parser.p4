    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_metadata;
    }


    state parse_metadata {
        mirror_h mirror_md = pkt.lookahead<mirror_h>();
        transition select(mirror_md.mirror_type) {
            1   : parse_mirror_md;
            // 2   : parse_mirror_md;
            default : accept;
        }
    }

    state parse_mirror_md {
        pkt.advance(8);
        transition accept;
    }

}
