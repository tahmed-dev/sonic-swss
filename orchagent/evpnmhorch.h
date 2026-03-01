#ifndef SWSS_EVPNMHORCH_H
#define SWSS_EVPNMHORCH_H

/*
 * EVPN MH v2.0 — Simplified evpnmhorch
 *
 * The v1.0 evpnmhorch managed PROTECTION NHGs, /32 server routes, and
 * L2/L3/HW failover modes in the control plane.  In v2.0, all failover
 * logic moves into VPP via the es-protect virtual interface.
 *
 * What remains:
 *   - DF (Designated Forwarder) election state from FRR
 *   - ES interface association tracking (for portsorch DF queries)
 *   - ES state table consumption (EVPN_MH_ES_STATE_TABLE) — kept in
 *     fdbsyncd, consumed by VPP-SAI directly
 *
 * Removed:
 *   - PROTECTION NHG creation/management
 *   - /32 server route injection (addHwFrrServerRoute/removeHwFrrServerRoute)
 *   - L2/L3/HW failover mode selection
 *   - Tunnel reroute on port down/up
 *   - Peer VTEP management
 */

#include <vector>
#include <map>
#include <set>

#include "orch.h"
#include "observer.h"

struct EsCacheEntry
{
    bool is_df;

    EsCacheEntry() : is_df(true) {}
    EsCacheEntry(bool is_df) : is_df(is_df) {}
};

class EvpnMhOrch : public Orch
{
public:
    EvpnMhOrch(vector<TableConnector> &connectors);
    ~EvpnMhOrch();

    bool isPortInterfaceAssociatedToEs(const std::string &port_name);
    bool isPortAndVlanAssociatedToEs(const std::string &port_name, sai_vlan_id_t vlan_id);
    bool isInterfaceDF(const std::string &port_name, sai_vlan_id_t vlan_id);

private:
    std::map<std::string, struct EsCacheEntry *> m_esDataMap;
    std::map<std::string, bool> m_esIntfMap;

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
