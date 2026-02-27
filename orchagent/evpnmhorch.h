#ifndef SWSS_EVPNMHORCH_H
#define SWSS_EVPNMHORCH_H

#include <vector>
#include <map>
#include <set>

#include "orch.h"
#include "observer.h"
#include "ipprefix.h"

/* Failover mode for EVPN MH Ethernet Segments */
enum class EvpnMhFailoverMode {
    L2,        // MAC reroute to L2 VxLAN tunnel
    L3,        // Host route injection via L3 VxLAN tunnel
    HW,        // HW FRR protection groups (pre-provisioned NHG with backup paths)
    AUTO       // HW if supported, else L3 if L3VNI available, else L2
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

    /* Server IPs behind an ES port (from ConfigDB) */
    std::vector<IpPrefix> getServerIpsForEsPort(const std::string &port_name);

    /* Check if an IP is a server behind an ES port with HW failover mode.
     * Used by neighorch to set SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE. */
    bool isHwFrrServerIp(const IpAddress &ip);

    /* HW FRR protection group management */
    sai_status_t createHwFrrProtectionGroups(const std::string &es_port);
    sai_status_t removeHwFrrProtectionGroups(const std::string &es_port);
    sai_status_t updateHwFrrActiveSisters(const std::string &es_port,
                                          uint8_t new_active_mask);
    sai_status_t refreshHwFrrSisterState(const std::string &es_port);

    /* HW FRR local port failover: swap routes to tunnel on port down,
     * restore to PROTECTION NHG on port up.  Called by fdborch. */
    sai_status_t handleHwFrrLocalPortDown(const std::string &es_port);
    sai_status_t handleHwFrrLocalPortUp(const std::string &es_port);

    /* Check if the peer VTEP still has the ES active (via FRR zebra) */
    bool isPeerEsActive(const std::string &port_name);

    /* Get the set of active remote VTEPs for an ES port (via FRR) */
    std::set<std::string> getActiveRemoteVteps(const std::string &port_name);

private:
    std::map<std::string, struct EsCacheEntry *> m_esDataMap;
    std::map<std::string, bool> m_esIntfMap;

    /* Per-port failover mode from EVPN_ETHERNET_SEGMENT table */
    std::map<std::string, EvpnMhFailoverMode> m_esFailoverMode;

    /* Per-ES peer VTEP IP (sister T1) from config — enables pre-provisioning
     * of tunnels, arp-term entries, and L3 nexthops at init time */
    std::map<std::string, std::string> m_esPeerVtep;
    std::map<std::string, std::string> m_esSysMac;
    std::map<std::string, std::vector<std::string>> m_esPeerVtepList; /* HW FRR: ordered sister VTEP IPs */

    /* Per-ES server IPs from config — static mapping of port → server overlay IPs
     * for L3 failover host route injection (avoids dependency on FDB/neighbor table) */
    std::map<std::string, std::vector<IpPrefix>> m_esServerIps;

    /* Cache of L3 VxLAN tunnel nexthops: peer_vtep_ip → SAI nexthop OID */
    std::map<std::string, sai_object_id_t> m_l3TunnelNexthops;

    /* HW FRR protection groups: per-ES port tracking of SAI objects */

    /* Per-sister tunnel nexthop */
    struct SisterVtep {
        IpAddress vtep_ip;                  // Sister T1's VTEP loopback IP
        sai_object_id_t nh_tunnel_oid;      // SAI NH via L3 VxLAN tunnel
        uint8_t index;                      // Position in sister list (bit position)
    };

    /* Pre-provisioned HW_PROTECTION NHG for a specific subset of sisters.
     * Indexed by bitmask of active sisters in the subset. */
    struct HwProtNhg {
        uint8_t sister_mask;                // Bitmask: which sisters are in this NHG
        sai_object_id_t nhg_oid;            // SAI HW_PROTECTION NHG OID
        std::vector<sai_object_id_t> member_oids;  // Members inside this NHG
    };

    /* Per-server PROTECTION group: one per server IP per ES port */
    struct HwFrrProtectionGroup {
        sai_object_id_t prot_nhg_oid;       // PROTECTION NHG
        sai_object_id_t primary_member_oid; // PRIMARY member in PROTECTION NHG
        sai_object_id_t standby_member_oid; // STANDBY member (→ active HwProtNhg)
        sai_object_id_t nh_local_oid;       // Local NH (borrowed from neighorch, NOT owned)
        sai_object_id_t nh_original_oid;    // Original NH on the /32 route (for restoration)
        IpPrefix server_ip;                 // Server overlay IP
        bool owns_local_nh;                 // true if we created nh_local_oid (must delete on teardown)
        bool owns_route;                    // true if we created route (must delete vs restore on teardown)
    };

    /* Per-ES port: all HW FRR state */
    struct EsHwFrrState {
        std::string es_port;                        // ES port alias (e.g. "PortChannel0")
        std::vector<SisterVtep> sisters;            // Ordered sister list
        std::map<uint8_t, HwProtNhg> nhg_subsets;   // mask → pre-provisioned NHG (2^N - 1 entries)
        std::vector<HwFrrProtectionGroup> prot_groups;  // Per-server PROTECTION groups
        uint8_t active_sister_mask;                 // Currently active sisters
    };

    std::map<std::string, EsHwFrrState> m_hwFrrState;

    /* Whether peer state has been initialized */
    bool m_peerStateInitDone = false;

    struct EsCacheEntry *getEsCache(const std::string &key);
    struct EsCacheEntry *getEsCacheForPort(const std::string &key);
    bool updateEsCache(string &key, KeyOpFieldsValuesTuple &t);
    bool deleteEsCache(string &key);
    void doEvpnEsDfTask(Consumer &consumer);
    void doEvpnEsIntfTask(Consumer &consumer);
    void doEvpnMhEsStateTask(Consumer &consumer);
    bool vlanMembersApplyNonDF(string port_name);
    std::string stripVlanFromInterfaceName(const std::string interfaceName);

    void doTask(Consumer &consumer);
};

#endif /* SWSS_EVPNMHORCH_H */
