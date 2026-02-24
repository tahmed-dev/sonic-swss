#ifndef SWSS_EVPNMHORCH_H
#define SWSS_EVPNMHORCH_H

#include <vector>
#include <map>

#include "orch.h"
#include "observer.h"
#include "ipprefix.h"

/* Failover mode for EVPN MH Ethernet Segments */
enum class EvpnMhFailoverMode {
    L2,        // MAC reroute to L2 VxLAN tunnel
    L3,        // Host route injection via L3 VxLAN tunnel
    AUTO       // L3 if L3VNI available, else L2
};

struct EsCacheEntry
{
    /*
     * Lifecycle of the DF role attribute (SAI_BRIDGE_PORT_ATTR_NON_DF):
     * - Port Creation/deletion: Handled by portsorch querying evpnMhOrch
     * - EVPN_DF_TABLE Updates: Handled by evpnMhOrch querying portsorch
     */
    bool is_df;

    EsCacheEntry()
    {
    }

    EsCacheEntry(bool is_df) : is_df(is_df)
    {
    }
};

class EvpnMhOrch : public Orch
{
public:
    EvpnMhOrch(vector<TableConnector> &connectors);
    ~EvpnMhOrch();

    bool isPortInterfaceAssociatedToEs(const std::string &port_name);
    bool isPortAndVlanAssociatedToEs(const std::string &port_name, sai_vlan_id_t vlan_id);
    bool isInterfaceDF(const std::string &port_name, sai_vlan_id_t vlan_id);

    /* Get all peer VTEP IPs for a given ES port (from EVPN Type-3 routes).
     * Returns the peer VTEP to reroute traffic to on local link failure. */
    std::string getPeerVtepForEsPort(const std::string &port_name);

    /* L3 dual-mode failover support */
    EvpnMhFailoverMode getEffectiveFailoverMode(const std::string &port_alias);
    sai_object_id_t getVrfOidForEsPort(const std::string &port_alias);
    sai_object_id_t getL3TunnelNexthop(const std::string &peer_vtep_ip);

    /* Sister T1 peer VTEP */
    std::string getPeerVtepForEsPortConfig(const std::string &port_name);
    void initPeerState();

private:
    std::map<std::string, struct EsCacheEntry *> m_esDataMap;
    std::map<std::string, bool> m_esIntfMap;

    /* Per-port failover mode from EVPN_ETHERNET_SEGMENT table */
    std::map<std::string, EvpnMhFailoverMode> m_esFailoverMode;

    /* Per-ES peer VTEP IP (sister T1) from config — enables pre-provisioning
     * of tunnels, arp-term entries, and L3 nexthops at init time */
    std::map<std::string, std::string> m_esPeerVtep;

    /* Cache of L3 VxLAN tunnel nexthops: peer_vtep_ip → SAI nexthop OID */
    std::map<std::string, sai_object_id_t> m_l3TunnelNexthops;

    /* Whether peer state has been initialized */
    bool m_peerStateInitDone = false;

    struct EsCacheEntry *getEsCache(const std::string &key);
    struct EsCacheEntry *getEsCacheForPort(const std::string &key);
    bool updateEsCache(string &key, KeyOpFieldsValuesTuple &t);
    bool deleteEsCache(string &key);
    void doEvpnEsDfTask(Consumer &consumer);
    void doEvpnEsIntfTask(Consumer &consumer);
    bool vlanMembersApplyNonDF(string port_name);
    std::string stripVlanFromInterfaceName(const std::string interfaceName);

    void doTask(Consumer &consumer);
};

#endif /* SWSS_EVPNMHORCH_H */
