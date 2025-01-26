
/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    ParserCounter() counter;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset) {
            0x05 : parse_tcp_after_options;
            // 0x06 : parse_tcp_options_06;
            // 0x07 : parse_tcp_options_07;
            0x08 : parse_tcp_options_08; 
            // 0x09 : parse_tcp_options_09;
            // 0x0a : parse_tcp_options_10;
            // 0x0b : parse_tcp_options_11;
            // 0x0c : parse_tcp_options_12;
            // 0x0d : parse_tcp_options_13;
            // 0x0e : parse_tcp_options_14;
            // 0x0f : parse_tcp_options_15;
            default: accept;
        }
    }

    // state parse_tcp_options_6 {pkt.extract(hdr.tcp_options_6);transition parse_tcp_after_options;}
    // state parse_tcp_options_7 {pkt.extract(hdr.tcp_options_7);transition parse_tcp_after_options;}
    // state parse_tcp_options_8 {pkt.extract(hdr.tcp_options_8);transition parse_tcp_after_options;}
    // state parse_tcp_options_9 {pkt.extract(hdr.tcp_options_9);transition parse_tcp_after_options;}
    // state parse_tcp_options_10 {pkt.extract(hdr.tcp_options_10);transition parse_tcp_after_options;}
    // state parse_tcp_options_11 {pkt.extract(hdr.tcp_options_11);transition parse_tcp_after_options;}
    // state parse_tcp_options_12 {pkt.extract(hdr.tcp_options_12);transition parse_tcp_after_options;}
    // state parse_tcp_options_13 {pkt.extract(hdr.tcp_options_13);transition parse_tcp_after_options;}
    // state parse_tcp_options_14 {pkt.extract(hdr.tcp_options_14);transition parse_tcp_after_options;}
    // state parse_tcp_options_15 {pkt.extract(hdr.tcp_options_15);transition parse_tcp_after_options;}

    // state parse_tcp_options_06 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_07 {pkt.advance(32);transition parse_tcp_after_options;}
    state parse_tcp_options_08 {pkt.advance(96);transition parse_tcp_after_options;}
    // state parse_tcp_options_09 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_10 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_11 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_12 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_13 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_14 {pkt.advance(32);transition parse_tcp_after_options;}
    // state parse_tcp_options_15 {pkt.advance(32);transition parse_tcp_after_options;}

    state parse_tcp_after_options {
        transition select(hdr.tcp.dst_port) {
            443: parse_tls;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tls {
        pkt.extract(hdr.tls);
        transition select(hdr.tls.type) {
            0x16: parse_tls_handshake;
            default: accept;
        }  
    }

    state parse_tls_handshake {
        pkt.extract(hdr.tls_handshake);
        transition select(hdr.tls_handshake.type) {
            0x01: parse_session_ids;
            0x02: parse_session_ids;
            default: accept;
        }
    }

    state parse_session_ids {
        pkt.extract(hdr.hello_session);
        transition select(hdr.hello_session.len[7:6]) {
            0x00: parse_session_ids_;
            default: unparsed_session;
        }
    }

    state unparsed_session {
        meta.unparsed = SESSION_LEN;
        transition accept;
    }

    state parse_session_ids_ {
        transition select(hdr.hello_session.len[5:4]) {
            0x00: skip_session_len_16_0;
            0x01: skip_session_len_16_1;
            0x02: skip_session_len_32_1;
            0x03: skip_session_len_48_1;
        }
    }

    state skip_session_len_16_0 {
        transition select(hdr.hello_session.len[3:3]) {
            0x00: skip_session_len_8_0;
            0x01: skip_session_len_8_1;
        }
    }

    state skip_session_len_16_1 {
        pkt.advance(128);
        transition skip_session_len_16_0;
    }

    state skip_session_len_32_1 {
        pkt.advance(256);
        transition skip_session_len_16_0;
    }

    state skip_session_len_48_1 {
        pkt.advance(384);
        transition skip_session_len_16_0;
    }

    state skip_session_len_8_0 {
        transition select(hdr.hello_session.len[2:0]) {
            0x00: hello_cipher;
            0x01: skip_session_len_1;
            0x02: skip_session_len_2;
            0x03: skip_session_len_3;
            0x04: skip_session_len_4;
            0x05: skip_session_len_5;
            0x06: skip_session_len_6;
            0x07: skip_session_len_7;
        }
    }

    state skip_session_len_8_1 {
        pkt.advance(64);
        transition skip_session_len_8_0;
    }

    state skip_session_len_1 {pkt.advance(08); transition hello_cipher;}
    state skip_session_len_2 {pkt.advance(16); transition hello_cipher;}
    state skip_session_len_3 {pkt.advance(24); transition hello_cipher;}
    state skip_session_len_4 {pkt.advance(32); transition hello_cipher;}
    state skip_session_len_5 {pkt.advance(40); transition hello_cipher;}
    state skip_session_len_6 {pkt.advance(48); transition hello_cipher;}
    state skip_session_len_7 {pkt.advance(56); transition hello_cipher;}


    state hello_cipher {
        pkt.extract(hdr.hello_ciphers);
        transition select(hdr.hello_ciphers.len[15:7]) {
            0x00: hello_cipher_;
            default: unparsed_cipher;
        }
    }

    state unparsed_cipher {
        meta.unparsed = CIPHER_LIM;
        transition accept;
    }

    state hello_cipher_ {
        transition select(hdr.hello_ciphers.len[6:6]) {
            0x00: parse_cipher_len_64_0;
            0x01: parse_cipher_len_64_1;
            default: accept;
        }
    }

    state parse_cipher_len_64_0 {
        transition select(hdr.hello_ciphers.len[5:4]) {
            0x00: parse_cipher_len_16_0;
            0x01: parse_cipher_len_16_1;
            0x02: parse_cipher_len_32_1;
            0x03: parse_cipher_len_48_1;
        }
    }

    state parse_cipher_len_64_1 {
        pkt.advance(512);
        transition parse_cipher_len_64_0;
    }

    state parse_cipher_len_16_0 {
        transition select(hdr.hello_ciphers.len[3:1]) {
            0x00: parse_compressions;
            0x01: parse_cipher_len_1;
            0x02: parse_cipher_len_2;
            0x03: parse_cipher_len_3;
            0x04: parse_cipher_len_4;
            0x05: parse_cipher_len_5;
            0x06: parse_cipher_len_6;
            0x07: parse_cipher_len_7;
        }
    }

    state parse_cipher_len_16_1 {
        pkt.advance(128);
        transition parse_cipher_len_16_0;
    }

    state parse_cipher_len_32_1 {
        pkt.advance(256);
        transition parse_cipher_len_16_0;
    }

    state parse_cipher_len_48_1 {
        pkt.advance(384);
        transition parse_cipher_len_16_0;
    }

    state parse_cipher_len_1 {pkt.advance(016); transition parse_compressions;}
    state parse_cipher_len_2 {pkt.advance(032); transition parse_compressions;}
    state parse_cipher_len_3 {pkt.advance(048); transition parse_compressions;}
    state parse_cipher_len_4 {pkt.advance(064); transition parse_compressions;}
    state parse_cipher_len_5 {pkt.advance(080); transition parse_compressions;}
    state parse_cipher_len_6 {pkt.advance(096); transition parse_compressions;}
    state parse_cipher_len_7 {pkt.advance(112); transition parse_compressions;}

    state parse_compressions {
        pkt.extract(hdr.compressions);
        transition select (hdr.compressions.len) {
            0x01: parse_compressions_len_1;
            default: unparsed_compression;
        }
    }
    state unparsed_compression {
        meta.unparsed = COMP_LEN;
        transition accept;
    }
    state parse_compressions_len_1 {
        pkt.advance(8);
        transition parse_extensions_len;
    }

    state parse_extensions_len {
        pkt.extract(hdr.extensions_len);
        transition select(hdr.extensions_len.len) {
            0x0000: accept;
            default: parse_extension;
        }
    }

    /////////////////////////////////////////////////////////////////////////////
    //////////////////////////  Extension Parsing Start ////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    // state set_counters {
    //     counter.set((bit<8>)0x2);
    //     transition parse_extension;
    //     }

    state parse_extension {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[31:16]) {
            0x0000: parse_server_name;
            default: skip_extension;
        }
    }

    state unparsed_extension {
        meta.unparsed = EXT_LIM;
        transition accept;
    }

    state skip_extension {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[15:0]) {
            0x00: skip_extension_len_0; 
            0x01: skip_extension_len_1;
            0x02: skip_extension_len_2;
            0x03: skip_extension_len_3;
            0x04: skip_extension_len_4;
            0x05: skip_extension_len_5;
            0x06: skip_extension_len_6;
            0x07: skip_extension_len_7;
            0x08: skip_extension_len_8;
            0x09: skip_extension_len_9;
            0x0a: skip_extension_len_10;
            0x0b: skip_extension_len_11;
            0x0c: skip_extension_len_12;
            0x0d: skip_extension_len_13;
            0x0e: skip_extension_len_14;
            0x0f: skip_extension_len_15;
            0x10: skip_extension_len_16;
            0x11: skip_extension_len_17;
            0x12: skip_extension_len_18;
            0x13: skip_extension_len_19;
            0x14: skip_extension_len_20;
            0x15: skip_extension_len_21;
            0x16: skip_extension_len_22;
            0x17: skip_extension_len_23;
            0x18: skip_extension_len_24;
            0x19: skip_extension_len_25;
            0x1a: skip_extension_len_26;
            0x1b: skip_extension_len_27;
            0x1c: skip_extension_len_28;
            0x1d: skip_extension_len_29;
            0x1e: skip_extension_len_30;

            // 0x2b: temp_state_parse_43;
            // default: accept;
            default: parse_extension_long; 
        }
    }

    state skip_extension_len_0 {pkt.advance(32); transition parse_extension; }
    state skip_extension_len_1 {pkt.advance(40); transition parse_extension; }
    state skip_extension_len_2 {pkt.advance(48); transition parse_extension; }
    state skip_extension_len_3 {pkt.advance(56); transition parse_extension; }
    state skip_extension_len_4 {pkt.advance(64); transition parse_extension; }
    state skip_extension_len_5 {pkt.advance(72); transition parse_extension; }
    state skip_extension_len_6 {pkt.advance(80); transition parse_extension; }
    state skip_extension_len_7 {pkt.advance(88); transition parse_extension; }
    state skip_extension_len_8 {pkt.advance(96); transition parse_extension; }
    state skip_extension_len_9 {pkt.advance(104); transition parse_extension;}

    state skip_extension_len_10 {pkt.advance(112); transition parse_extension;}
    state skip_extension_len_11 {pkt.advance(120); transition parse_extension;}
    state skip_extension_len_12 {pkt.advance(128); transition parse_extension;}
    state skip_extension_len_13 {pkt.advance(136); transition parse_extension;}
    state skip_extension_len_14 {pkt.advance(144); transition parse_extension;}
    state skip_extension_len_15 {pkt.advance(152); transition parse_extension;}
    state skip_extension_len_16 {pkt.advance(160); transition parse_extension;}
    state skip_extension_len_17 {pkt.advance(136); transition parse_extension;}
    state skip_extension_len_18 {pkt.advance(144); transition parse_extension;}
    state skip_extension_len_19 {pkt.advance(152); transition parse_extension;}
    state skip_extension_len_20 {pkt.advance(160); transition parse_extension;}
    state skip_extension_len_21 {pkt.advance(168); transition parse_extension;}
    state skip_extension_len_22 {pkt.advance(176); transition parse_extension;}
    state skip_extension_len_23 {pkt.advance(184); transition parse_extension;}
    state skip_extension_len_24 {pkt.advance(192); transition parse_extension;}
    state skip_extension_len_25 {pkt.advance(200); transition parse_extension;}
    state skip_extension_len_26 {pkt.advance(208); transition parse_extension;}
    state skip_extension_len_27 {pkt.advance(216); transition parse_extension;}
    state skip_extension_len_28 {pkt.advance(224); transition parse_extension;}
    state skip_extension_len_29 {pkt.advance(232); transition parse_extension;}
    state skip_extension_len_30 {pkt.advance(240); transition parse_extension;}
    state skip_extension_len_31 {pkt.advance(248); transition parse_extension;}

    state temp_state_parse_43 {pkt.advance(376); transition parse_extension;}
    
    /////////////////////////////////////////////////////////////////////////////
    ///////////////////////////  Extension long start //////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    state parse_extension_long {
        // counter.decrement((bit<8>)0x2);
        // transition parse_extension;
        pkt.extract(hdr.extension_long);
        transition select(hdr.extension_long.len[15:8]) {
            0x0000: skip_extension_long_stage_2; 
            default: unparsed_extension;
            // default: accept;
        }
    }

    state skip_extension_long_stage_2 {
        transition select(hdr.extension_long.len[7:4]) {
            0x00: skip_extension_long_len_16_0; 
            0x01: skip_extension_long_len_16;
            0x02: skip_extension_long_len_32; //Problem happens after here
            0x03: skip_extension_long_len_48;
            0x04: skip_extension_long_len_64;
            0x05: skip_extension_long_len_80;
            0x06: skip_extension_long_len_96;
            0x07: skip_extension_long_len_112;
            0x08: skip_extension_long_len_128;
            0x09: skip_extension_long_len_144;
            0x0a: skip_extension_long_len_160;
            0x0b: skip_extension_long_len_176;
            // 0x0c: skip_extension_long_len_192;
            // 0x0d: skip_extension_long_len_208;
            // 0x0e: skip_extension_long_len_224;
            // 0x0f: skip_extension_long_len_240;
            default: unparsed_extension;
        }
    }

    state skip_extension_long_len_16_0 {
        transition select(hdr.extension_long.len[3:0]) {
            0x00: parse_extension_stage_2;
            0x01: skip_extension_long_len_1;
            0x02: skip_extension_long_len_2;
            0x03: skip_extension_long_len_3;
            0x04: skip_extension_long_len_4;
            0x05: skip_extension_long_len_5;
            0x06: skip_extension_long_len_6;
            0x07: skip_extension_long_len_7;
            0x08: skip_extension_long_len_8;
            0x09: skip_extension_long_len_9;
            0x0a: skip_extension_long_len_10;
            0x0b: skip_extension_long_len_11;//Problem happens after here stress
            0x0c: skip_extension_long_len_12;
            0x0d: skip_extension_long_len_13;
            0x0e: skip_extension_long_len_14;
            0x0f: skip_extension_long_len_15;
            // default: accept;
        }
    }

    state skip_extension_long_len_1  {pkt.advance(08); transition parse_extension_stage_2; }
    state skip_extension_long_len_2  {pkt.advance(16); transition parse_extension_stage_2; }
    state skip_extension_long_len_3  {pkt.advance(24); transition parse_extension_stage_2; }
    state skip_extension_long_len_4  {pkt.advance(32); transition parse_extension_stage_2; }
    state skip_extension_long_len_5  {pkt.advance(40); transition parse_extension_stage_2; }
    state skip_extension_long_len_6  {pkt.advance(48); transition parse_extension_stage_2; }
    state skip_extension_long_len_7  {pkt.advance(56); transition parse_extension_stage_2; }
    state skip_extension_long_len_8  {pkt.advance(64); transition parse_extension_stage_2; }
    state skip_extension_long_len_9  {pkt.advance(72); transition parse_extension_stage_2; }
    state skip_extension_long_len_10 {pkt.advance(80); transition parse_extension_stage_2; }
    state skip_extension_long_len_11 {pkt.advance(88); transition parse_extension_stage_2; }
    state skip_extension_long_len_12 {pkt.advance(96); transition parse_extension_stage_2; }
    state skip_extension_long_len_13{pkt.advance(104); transition parse_extension_stage_2; }
    state skip_extension_long_len_14{pkt.advance(112); transition parse_extension_stage_2; }
    state skip_extension_long_len_15{pkt.advance(120); transition parse_extension_stage_2; }
    

    state skip_extension_long_len_16 {pkt.advance(128);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_32 {pkt.advance(256);transition skip_extension_long_len_16_0;} 
    state skip_extension_long_len_48 {pkt.advance(384);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_64 {pkt.advance(512);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_80 {pkt.advance(640);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_96 {pkt.advance(768);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_112 {pkt.advance(896);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_128 {pkt.advance(1024);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_144 {pkt.advance(1152);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_160 {pkt.advance(1280);transition skip_extension_long_len_16_0;}
    state skip_extension_long_len_176 {pkt.advance(1408);transition skip_extension_long_len_16_0;}
    // state skip_extension_long_len_192 {pkt.advance(1536);transition skip_extension_long_len_16_0;}
    // state skip_extension_long_len_208 {pkt.advance(1664);transition skip_extension_long_len_16_0;}
    // state skip_extension_long_len_224 {pkt.advance(1792);transition skip_extension_long_len_16_0;}
    // state skip_extension_long_len_240 {pkt.advance(1920);transition skip_extension_long_len_16_0;}

    /////////////////////////////////////////////////////////////////////////////
    ////////////////////////////  Extension long end ///////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    
    /////////////////////////////////////////////////////////////////////////////
    /////////////////////////  Extension stage 2 start /////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    state parse_extension_stage_2 {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[31:16]) {
            0x0000: parse_server_name;
            default: skip_extension_stage_2;
        }
    }

    state skip_extension_stage_2 {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[15:0]) {
            0x00: skip_extension_stage_2_len_0; 
            0x01: skip_extension_stage_2_len_1;
            0x02: skip_extension_stage_2_len_2;
            0x03: skip_extension_stage_2_len_3;
            0x04: skip_extension_stage_2_len_4;
            0x05: skip_extension_stage_2_len_5;
            0x06: skip_extension_stage_2_len_6;
            0x07: skip_extension_stage_2_len_7;
            0x08: skip_extension_stage_2_len_8;
            0x09: skip_extension_stage_2_len_9;
            0x0a: skip_extension_stage_2_len_10;
            0x0b: skip_extension_stage_2_len_11;
            0x0c: skip_extension_stage_2_len_12;
            0x0d: skip_extension_stage_2_len_13;
            0x0e: skip_extension_stage_2_len_14;
            0x0f: skip_extension_stage_2_len_15;
            0x10: skip_extension_stage_2_len_16;
            0x11: skip_extension_stage_2_len_17;
            0x12: skip_extension_stage_2_len_18;
            0x13: skip_extension_stage_2_len_19;
            0x14: skip_extension_stage_2_len_20;
            0x15: skip_extension_stage_2_len_21;
            0x16: skip_extension_stage_2_len_22;
            0x17: skip_extension_stage_2_len_23;
            0x18: skip_extension_stage_2_len_24;
            0x19: skip_extension_stage_2_len_25;
            0x1a: skip_extension_stage_2_len_26;
            0x1b: skip_extension_stage_2_len_27;
            0x1c: skip_extension_stage_2_len_28;
            0x1d: skip_extension_stage_2_len_29;
            0x1e: skip_extension_stage_2_len_30;
            0x2b: accept;
            default: unparsed_extension; 
        }
    }

    state skip_extension_stage_2_len_0 {pkt.advance(32); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_1 {pkt.advance(40); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_2 {pkt.advance(48); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_3 {pkt.advance(56); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_4 {pkt.advance(64); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_5 {pkt.advance(72); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_6 {pkt.advance(80); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_7 {pkt.advance(88); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_8 {pkt.advance(96); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_9{pkt.advance(104); transition parse_extension_stage_2; }

    state skip_extension_stage_2_len_10 {pkt.advance(112); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_11 {pkt.advance(120); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_12 {pkt.advance(128); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_13 {pkt.advance(136); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_14 {pkt.advance(144); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_15 {pkt.advance(152); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_16 {pkt.advance(160); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_17 {pkt.advance(136); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_18 {pkt.advance(144); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_19 {pkt.advance(152); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_20 {pkt.advance(160); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_21 {pkt.advance(168); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_22 {pkt.advance(176); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_23 {pkt.advance(184); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_24 {pkt.advance(192); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_25 {pkt.advance(200); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_26 {pkt.advance(208); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_27 {pkt.advance(216); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_28 {pkt.advance(224); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_29 {pkt.advance(232); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_30 {pkt.advance(240); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_31 {pkt.advance(248); transition parse_extension_stage_2;}


    /////////////////////////////////////////////////////////////////////////////
    //////////////////////////  Extension stage 2 end //////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    

    state parse_server_name {
        pkt.extract(hdr.extension);
        pkt.extract(hdr.client_servername); 
        transition select(hdr.client_servername.sni_len[15:5]) {
            0x00: parse_server_name_;
            default: unparsed_sni;
        }
    }
    state unparsed_sni {
        meta.unparsed = SNI_LEN;
        transition accept;
    }

    state parse_server_name_ { 
        transition select(hdr.client_servername.sni_len[4:3]) {
            0x00: skip_part_16_8;
            0x01: extract_part_8;
            0x02: extract_part_16;
            0x03: extract_part_16_8;
        }
    }

    state skip_part_16_8 { 
        transition select(hdr.client_servername.sni_len[2:0]) {
            0x00: accept;
            0x01: extract_part_1;
            0x02: extract_part_2;
            0x03: extract_part_1_2;
            0x04: extract_part_4;
            0x05: extract_part_1_4;
            0x06: extract_part_2_4;
            0x07: extract_part_1_2_4;
        }
    }

    state extract_part_8 {
        pkt.extract(hdr.servername_part8);
        transition skip_part_16_8;
    }

    state extract_part_16 {
        pkt.extract(hdr.servername_part16);
        transition skip_part_16_8;
    }

    state extract_part_16_8 {
        pkt.extract(hdr.servername_part16);
        pkt.extract(hdr.servername_part8);
        transition skip_part_16_8;
    }

    state extract_part_1 {
        pkt.extract(hdr.servername_part1);
        transition accept;
    }
    state extract_part_2 {
        pkt.extract(hdr.servername_part2);
        transition accept;
    }
    state extract_part_1_2 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part1);
        transition accept;
    }
    state extract_part_4 {
        pkt.extract(hdr.servername_part4);
        transition accept;
    }
    state extract_part_1_4 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part1);
        transition accept;
    }
    state extract_part_2_4 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part2);
        transition accept;
    }
    state extract_part_1_2_4 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part1);
        transition accept;
    }

}