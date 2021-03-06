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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
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
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }
    
    state parse_tcp {
       packet.extract(hdr.tcp);
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
    // Store a boolean for all possible ports in registers
    register<bit<48>>(65535) last_time_flows_seen_at;
    // Alert bit
    register<bit<1>>(1) alert;
    register<bit<16>>(1)last_hash;
    bit<48> time_threshold = 10000000;
    //10 seconds in microseconds
    register<bit<48>>(3) reg1;
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
            if(hdr.tcp.isValid()) {
            	bit<16> flow_hash;
			    bit<32> flow_hash_cast;
			    bit<16> new_destPort;
			    bit<48> time_flow_seen_before;
			    hash(flow_hash, HashAlgorithm.csum16, (bit<16>)0, {hdr.ipv4.srcAddr,
		    		hdr.ipv4.dstAddr,
					hdr.tcp.dstPort},
					(bit<16>)65535);
				flow_hash_cast = (bit<32>)flow_hash;
				last_hash.write(0, flow_hash);
				last_time_flows_seen_at.read(time_flow_seen_before, flow_hash_cast);
				if(time_flow_seen_before == 0) {
					//We haven't seen the flow of this packet before, record it, check lower ports for this flow
					last_time_flows_seen_at.write(flow_hash_cast, standard_metadata.ingress_global_timestamp);
					new_destPort = hdr.tcp.dstPort - 1;
					hash(flow_hash, HashAlgorithm.csum16, (bit<16>)0, {hdr.ipv4.srcAddr,
			    		hdr.ipv4.dstAddr,
						new_destPort},
						(bit<16>)65535);
					flow_hash_cast = (bit<32>)flow_hash;
					last_time_flows_seen_at.read(time_flow_seen_before, flow_hash_cast);
					if (time_flow_seen_before != 0) {
						reg1.write(0,standard_metadata.ingress_global_timestamp);
						reg1.write(1,time_flow_seen_before);
						reg1.write(2,standard_metadata.ingress_global_timestamp - time_flow_seen_before);
						//We have record a time for this flow before
						if(time_threshold >= standard_metadata.ingress_global_timestamp - time_flow_seen_before) {
							alert.write(0,1);
							//We've seen the lower port less than time_threshold ago, keep checking
							//alert.write(0,1);
							// last_time_flows_seen_at.write(flow_hash_cast, 1);
							// new_destPort = new_destPort - 1;
							// hash(flow_hash, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
					  //   		hdr.ipv4.dstAddr,
							// 	new_destPort},
							// 	(bit<16>)65535);
							// flow_hash_cast = (bit<32>)flow_hash;
							// last_time_flows_seen_at.read(time_flow_seen_before, flow_hash_cast);

							// 	}
							// }
						}
					}
				}
                ipv4_lpm.apply();
            }
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
        packet.emit(hdr.tcp);
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
