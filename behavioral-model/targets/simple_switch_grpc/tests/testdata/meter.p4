/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <core.p4>
#include <v1model.p4>

struct Headers {}

struct Meta {
    bit<3> color;
}

parser p(packet_in b, out Headers h,
         inout Meta m, inout standard_metadata_t sm) {
    state start {
        transition accept;
    }
}

control vrfy(inout Headers h, inout Meta m) { apply {} }
control update(inout Headers h, inout Meta m) { apply {} }

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {}
}

control deparser(packet_out b, in Headers h) {
    apply {}
}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    direct_meter<bit<3> >(MeterType.packets) mtr;
    action port_redirect() {
        sm.egress_spec = sm.ingress_port;
        mtr.read(m.color);
    }
    table t_redirect {
        key = { sm.ingress_port : exact; }
        actions = { port_redirect; }
        meters = mtr;
    }
    apply { t_redirect.apply(); }
}

V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
