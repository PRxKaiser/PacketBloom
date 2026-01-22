// g++ -O2 -shared -fPIC $(python3 -m pybind11 --includes) backend/packetbloom_backend.cpp -lpcap -o backend$(python3-config --extension-suffix)

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;
static const int ETHER_HDR_LEN = 14;

struct Rec {
    std::string src_ip, dst_ip, proto;
    int sport=0, dport=0, length=0;
    double ts=0.0;
};

struct CaptureCtx {
    std::vector<Rec> records;
    int max_packets=0;
    pcap_dumper_t *dumper=nullptr;
};

static void handler(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet){
    auto *ctx=reinterpret_cast<CaptureCtx*>(user);
    if((int)ctx->records.size()>=ctx->max_packets) return;
    const struct ip* ip_hdr=(const struct ip*)(packet+ETHER_HDR_LEN);
    Rec r; r.length=hdr->len; r.ts=hdr->ts.tv_sec+hdr->ts.tv_usec/1e6;
    char src[INET_ADDRSTRLEN],dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ip_hdr->ip_src,src,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&ip_hdr->ip_dst,dst,INET_ADDRSTRLEN);
    r.src_ip=src; r.dst_ip=dst;
    const u_char* l4=packet+ETHER_HDR_LEN+(ip_hdr->ip_hl*4);
    if(ip_hdr->ip_p==IPPROTO_TCP){ r.proto="TCP"; const struct tcphdr* tcp=(const struct tcphdr*)l4; r.sport=ntohs(tcp->source); r.dport=ntohs(tcp->dest);}
    else if(ip_hdr->ip_p==IPPROTO_UDP){ r.proto="UDP"; const struct udphdr* udp=(const struct udphdr*)l4; r.sport=ntohs(udp->source); r.dport=ntohs(udp->dest);}
    else if(ip_hdr->ip_p==IPPROTO_ICMP){ r.proto="ICMP"; }
    else r.proto="OTHER";
    ctx->records.push_back(r);
    if(ctx->dumper) pcap_dump((u_char*)ctx->dumper,hdr,packet);
}

std::vector<Rec> capture_packets(const std::string& iface,int max_packets,int timeout_ms,const std::string& dumpfile=""){
    char errbuf[PCAP_ERRBUF_SIZE]; pcap_t *handle=pcap_open_live(iface.c_str(),BUFSIZ,1,timeout_ms,errbuf);
    if(!handle) throw std::runtime_error(errbuf);
    pcap_dumper_t *dumper=nullptr;
    if(!dumpfile.empty()){ dumper=pcap_dump_open(handle,dumpfile.c_str()); if(!dumper){pcap_close(handle); throw std::runtime_error("pcap_dump_open failed");}}
    CaptureCtx ctx; ctx.max_packets=max_packets; ctx.dumper=dumper;
    if(pcap_loop(handle,max_packets,handler,(u_char*)&ctx)==-1){ if(dumper) pcap_dump_close(dumper); pcap_close(handle); throw std::runtime_error("pcap_loop error");}
    if(dumper) pcap_dump_close(dumper); pcap_close(handle);
    return ctx.records;
}

PYBIND11_MODULE(backend,m){
    py::class_<Rec>(m,"Rec")
        .def_readonly("src_ip",&Rec::src_ip).def_readonly("dst_ip",&Rec::dst_ip)
        .def_readonly("proto",&Rec::proto).def_readonly("sport",&Rec::sport)
        .def_readonly("dport",&Rec::dport).def_readonly("length",&Rec::length)
        .def_readonly("ts",&Rec::ts);
    m.def("capture_packets",&capture_packets,
          py::arg("iface"),py::arg("max_packets")=200,
          py::arg("timeout_ms")=1000,py::arg("dumpfile")=std::string(""));
}
