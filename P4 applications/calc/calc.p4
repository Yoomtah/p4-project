/* -*- P4_16 -*- */

/*
 * P4 Calculator
 *
 * This program implements a simple protocol. It can be carried over Ethernet
 * (Ethertype 0x1234).
 *
 * The Protocol header looks like this:
 *
 *        0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |     Op        |
 * +----------------+----------------+----------------+---------------+
 * |                              Operand A                           |
 * +----------------+----------------+----------------+---------------+
 * |                              Operand B                           |
 * +----------------+----------------+----------------+---------------+
 * |                              Result                              |
 * +----------------+----------------+----------------+---------------+
 *
 * P is an ASCII Letter 'P' (0x50)
 * 4 is an ASCII Letter '4' (0x34)
 * Version is currently 0.1 (0x01)
 * Op is an operation to Perform:
 *   '+' (0x2b) Result = OperandA + OperandB
 *   '-' (0x2d) Result = OperandA - OperandB
 *   '&' (0x26) Result = OperandA & OperandB
 *   '|' (0x7c) Result = OperandA | OperandB
 *   '^' (0x5e) Result = OperandA ^ OperandB
 *   '/' (0x2f) Result = OperandA / OperandB
 *
 * The device receives a packet, performs the requested operation, fills in the 
 * result and sends the packet back out of the same port it came in on, while 
 * swapping the source and destination addresses.
 *
 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped 
 */

#include <core.p4>
#include <v1model.p4>

/*
 * Define the headers the program will recognize
 */

/*
 * Standard ethernet header 
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * This is a custom protocol header for the calculator. We'll use 
 * ethertype 0x1234 for is (see parser)
 */
const bit<16> P4CALC_ETYPE = 0x1234;
const bit<8>  P4CALC_P     = 0x50;   // 'P'
const bit<8>  P4CALC_4     = 0x34;   // '4'
const bit<8>  P4CALC_VER   = 0x01;   // v0.1
const bit<8>  P4CALC_PLUS  = 0x2b;   // '+'
const bit<8>  P4CALC_MINUS = 0x2d;   // '-'
const bit<8>  P4CALC_AND   = 0x26;   // '&'
const bit<8>  P4CALC_OR    = 0x7c;   // '|'
const bit<8>  P4CALC_CARET = 0x5e;   // '^'
const bit<8>  P4CALC_DIV   = 0x2f;   // '/'

header p4calc_t {
    bit<8>  p;
    bit<8>  four;
    bit<8>  ver;
    bit<8>  op;
    bit<32> operand_a;
    bit<32> operand_b;
    bit<32> res;
}

/*
 * All headers, used in the program needs to be assembed into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    p4calc_t     p4calc;
}

/*
 * All metadata, globally used in the program, also  needs to be assembed 
 * into a single struct. As in the case of the headers, we only need to 
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
 
struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            P4CALC_ETYPE : check_p4calc;
            default      : accept;
        }
    }
    
    state check_p4calc {
        transition select(packet.lookahead<p4calc_t>().p,
        packet.lookahead<p4calc_t>().four,
        packet.lookahead<p4calc_t>().ver) {
            (P4CALC_P, P4CALC_4, P4CALC_VER) : parse_p4calc;
            default                          : accept;
        }
    }
    
    state parse_p4calc {
        packet.extract(hdr.p4calc);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    bit<32> quotient = 0;
    bit<32> remainder = 0;
    
    action send_back(bit<32> result) {
        bit<48> tmp;

        /* Put the result back in */
        hdr.p4calc.res = result;
        
        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;
        
        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    
    action operation_add() {
        send_back(hdr.p4calc.operand_a + hdr.p4calc.operand_b);
    }
    
    action operation_sub() {
        send_back(hdr.p4calc.operand_a - hdr.p4calc.operand_b);
    }
    
    action operation_and() {
        send_back(hdr.p4calc.operand_a & hdr.p4calc.operand_b);
    }
    
    action operation_or() {
        send_back(hdr.p4calc.operand_a | hdr.p4calc.operand_b);
    }

    action operation_xor() {
        send_back(hdr.p4calc.operand_a ^ hdr.p4calc.operand_b);
    }
    action operation_div() {
        if (hdr.p4calc.operand_b != 0) {
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[31:31]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[31:31] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[30:30]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[30:30] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[29:29]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[29:29] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[28:28]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[28:28] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[27:27]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[27:27] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[26:26]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[26:26] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[25:25]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[25:25] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[24:24]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[24:24] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[23:23]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[23:23] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[22:22]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[22:22] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[21:21]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[21:21] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[20:20]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[20:20] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[19:19]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[19:19] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[18:18]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[18:18] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[17:17]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[17:17] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[16:16]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[16:16] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[15:15]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[15:15] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[14:14]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[14:14] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[13:13]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[13:13] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[12:12]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[12:12] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[11:11]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[11:11] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[10:10]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[10:10] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[9:9]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[9:9] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[8:8]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[8:8] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[7:7]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[7:7] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[6:6]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[6:6] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[5:5]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[5:5] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[4:4]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[4:4] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[3:3]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[3:3] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[2:2]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[2:2] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[1:1]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[1:1] = 1;
            }
            remainder = remainder << 1; //left shift remainder by 1 bit
            remainder[0:0] = hdr.p4calc.operand_a[0:0]; //Set the least-significant bit of remainder equal to bit index of the hdr.p4calc.operand_a
            if (remainder >= hdr.p4calc.operand_b) {
                remainder = remainder - hdr.p4calc.operand_b;
                quotient[0:0] = 1;
            }
        }
        send_back(quotient);
    }

    action operation_drop() {
        mark_to_drop();
    }
    
    table calculate {
        key = {
            hdr.p4calc.op        : exact;
        }
        actions = {
            operation_add;
            operation_sub;
            operation_and;
            operation_or;
            operation_xor;
            operation_drop;
            operation_div;
        }
        const default_action = operation_drop();
        const entries = {
            P4CALC_PLUS : operation_add();
            P4CALC_MINUS: operation_sub();
            P4CALC_AND  : operation_and();
            P4CALC_OR   : operation_or();
            P4CALC_CARET: operation_xor();
            P4CALC_DIV  : operation_div();
        }
    }

            
    apply {
        if (hdr.p4calc.isValid()) {
            calculate.apply();
        } else {
            operation_drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4calc);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
