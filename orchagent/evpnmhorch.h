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

    /* Peer T1 VTEP */
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
    sai_status_t updateHwFrrStandbyEcmp(const std::string &es_port,
                                        const std::set<std::string> &active_vteps);

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

    /* Per-ES peer VTEP IP (peer T1) from config — enables pre-provisioning
     * of tunnels, arp-term entries, and L3 nexthops at init time */
    std::map<std::string, std::string> m_esPeerVtep;
    std::map<std::string, std::string> m_esSysMac;
    std::map<std::string, std::vector<std::string>> m_esPeerVtepList; /* HW FRR: ordered peer VTEP IPs */

    /* Per-ES server IPs from config — static mapping of port → server overlay IPs
     * for L3 failover host route injection (avoids dependency on FDB/neighbor table) */
    std::map<std::string, std::vector<IpPrefix>> m_esServerIps;

    /* Cache of L3 VxLAN tunnel nexthops: peer_vtep_ip → SAI nexthop OID.
     * Shared across all ES ports — same peer VTEP uses same tunnel NH. */
    std::map<std::string, sai_object_id_t> m_l3TunnelNexthops;

    /* ===== HW FRR structures ===== */

    /* Per-peer tunnel nexthop info */
    struct PeerVtep {
        std::string vtep_ip;                // Peer T1's VTEP loopback IP
        sai_object_id_t nh_tunnel_oid;      // SAI NH via L3 VxLAN tunnel
        sai_object_id_t ecmp_member_oid;    // Member OID inside standby ECMP NHG
    };

    /* Per-server /32 route entry referencing the ES's PROTECTION NHG */
    struct HwFrrServerRoute {
        IpPrefix server_ip;                 // Server overlay IP (e.g. 10.0.0.2/32)
        sai_object_id_t nh_local_oid;       // Local NH (via bvi/VLAN RIF)
        bool owns_local_nh;                 // true if we created nh_local_oid
        bool owns_route;                    // true if we created route_entry
    };

    /*
     * Per-ES HW FRR state.
     *
     * Each Ethernet Segment gets ONE PROTECTION NHG:
     *   - PRIMARY member: local NH (via bvi) with MONITORED_OBJECT = PortChannel
     *   - STANDBY member: ECMP NHG across all active peer VTEP tunnel NHs
     *
     * All server /32 routes on this ES point to the same PROTECTION NHG.
     * On link failure: ASIC instantly switches to standby ECMP NHG.
     * On EVPN Type-4 update: standby ECMP NHG members are reprogrammed.
     */
    struct EsHwFrrState {
        std::string es_port;                        // ES port alias (e.g. "PortChannel0")

        /* The single PROTECTION NHG for this ES */
        sai_object_id_t prot_nhg_oid;               // PROTECTION NHG
        sai_object_id_t primary_member_oid;          // PRIMARY member in PROTECTION NHG
        sai_object_id_t standby_member_oid;          // STANDBY member → standby_ecmp_nhg

        /* Standby path: ECMP NHG across peer VTEP tunnels */
        sai_object_id_t standby_ecmp_nhg_oid;        // ECMP NHG (standby target)
        std::vector<PeerVtep> peers;                 // Peer VTEPs with tunnel NHs + ECMP member OIDs

        /* A single local NH used as PRIMARY (via VLAN RIF) — created once,
         * used for PROTECTION NHG primary member. We create an IP NH pointing
         * at the first server IP (the NH resolves via BVI/RIF, actual dst IP
         * doesn't matter for the PROTECTION selection — it's the monitored
         * object state that drives primary↔standby switchover). */
        sai_object_id_t nh_local_oid;                // Local NH for primary path
        bool owns_local_nh;                          // true if we created it

        /* Per-server /32 routes all pointing to prot_nhg_oid */
        std::vector<HwFrrServerRoute> server_routes;

        EsHwFrrState()
            : prot_nhg_oid(SAI_NULL_OBJECT_ID)
            , primary_member_oid(SAI_NULL_OBJECT_ID)
            , standby_member_oid(SAI_NULL_OBJECT_ID)
            , standby_ecmp_nhg_oid(SAI_NULL_OBJECT_ID)
            , nh_local_oid(SAI_NULL_OBJECT_ID)
            , owns_local_nh(false)
        {}
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
