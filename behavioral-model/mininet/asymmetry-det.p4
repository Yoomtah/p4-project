/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}



struct metadata {

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {




    
    bit<48> time_threshold = 10000000000000;
    //1 second in microseconds
    //The simple topology has 18 possible ingress egress combos (not all will be used)
    //I only care about h1 and h2 and they both use 1 to go to host and 2 to send out
    //Count the number of packets in the ingress/egress combo
    register<bit<32>>(1) flow_into_my_host;
    register<bit<32>>(1) flow_out_to_other_host;
    register<bit<32>>(1) flow_ratio;
    register<bit<48>>(1) time_diff;
    //Counts always need to be at least 1
    bit<32> count_packets_in = 1;
    bit<32> count_packets_out = 1;
    //Record the time we start each counter
    register<bit<48>>(1) counter_start_time;
    //In microseconds
    //Current va
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    
    apply {
        if (hdr.ipv4.isValid()) {
            bit<48> start_time = 0;
            counter_start_time.read(start_time, 0);
            flow_into_my_host.read(count_packets_in, 0);
            flow_out_to_other_host.read(count_packets_out, 0);
            if (start_time == 0) {
                //We must just be starting out
                counter_start_time.write(0, standard_metadata.ingress_global_timestamp);
                //Counts always need to be at least 1
                flow_into_my_host.write(0, 1);
                flow_out_to_other_host.write(0, 1);
            }
        	if (hdr.ipv4.dstAddr == 0x0a000101) {
                //Packet has come off the link between the switches
                count_packets_in = count_packets_in + 1;
                flow_into_my_host.write(0, count_packets_in);
            }
            if (hdr.ipv4.dstAddr == 0x0a000102) {
                //Packet has come from the host on that switch
                count_packets_out = count_packets_out + 1;
                flow_out_to_other_host.write(0, count_packets_out);
            }
            if (standard_metadata.ingress_global_timestamp - start_time >= time_threshold) {
                //A second or more has passed
                //Do division
                //count packets out is the numerator
                //counts packets in is the denominator
                //So out / in
                bit<32> quotient = 0;
                bit<32> remainder = 0;
                if (count_packets_in != 0) {
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[31:31]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[31:31] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[30:30]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[30:30] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[29:29]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[29:29] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[28:28]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[28:28] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[27:27]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[27:27] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[26:26]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[26:26] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[25:25]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[25:25] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[24:24]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[24:24] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[23:23]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[23:23] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[22:22]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[22:22] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[21:21]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[21:21] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[20:20]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[20:20] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[19:19]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[19:19] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[18:18]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[18:18] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[17:17]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[17:17] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[16:16]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[16:16] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[15:15]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[15:15] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[14:14]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[14:14] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[13:13]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[13:13] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[12:12]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[12:12] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[11:11]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[11:11] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[10:10]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[10:10] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[9:9]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[9:9] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[8:8]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[8:8] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[7:7]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[7:7] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[6:6]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[6:6] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[5:5]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[5:5] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[4:4]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[4:4] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[3:3]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[3:3] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[2:2]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[2:2] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[1:1]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[1:1] = 1;
                    }
                    remainder = remainder << 1; //left shift remainder by 1 bit
                    remainder[0:0] = count_packets_out[0:0]; //Set the least-significant bit of remainder equal to bit index of the count_packets_out
                    if (remainder >= count_packets_in) {
                        remainder = remainder - count_packets_in;
                        quotient[0:0] = 1;
                    }
                    flow_ratio.write(0, quotient);
                }
                else {
                    flow_ratio.write(0, quotient);
                }
                // Reset everything
                count_packets_in = 1;
                flow_into_my_host.write(0, count_packets_in);
                count_packets_out = 1;
                flow_out_to_other_host.write(0, count_packets_out);
                counter_start_time.write(0, standard_metadata.ingress_global_timestamp);
            }
            time_diff.write(0, standard_metadata.ingress_global_timestamp - start_time);
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
