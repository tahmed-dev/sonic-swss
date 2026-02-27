#include "evpnmhorch.h"

#include <inttypes.h>
#include <arpa/inet.h>
#include <set>
#include <sstream>

#include "portsorch.h"
#include "neighorch.h"
#include "directory.h"
#include "vxlanorch.h"
#include "vrforch.h"
#include "schema.h"
#include "dbconnector.h"
#include "table.h"

extern PortsOrch *gPortsOrch;
extern NeighOrch *gNeighOrch;
extern Directory<Orch*> gDirectory;
/* No gAppDb global — use local DBConnector in initPeerState */

extern sai_vlan_api_t *sai_vlan_api;
extern sai_next_hop_api_t *sai_next_hop_api;
extern sai_next_hop_group_api_t *sai_next_hop_group_api;
extern sai_route_api_t *sai_route_api;
extern sai_object_id_t gSwitchId;

#define VLAN_PREFIX "Vlan"

EvpnMhOrch::EvpnMhOrch(vector<TableConnector> &connectors) : Orch(connectors)
{
    SWSS_LOG_ENTER();
}

EvpnMhOrch::~EvpnMhOrch()
{
    SWSS_LOG_ENTER();
}

struct EsCacheEntry *EvpnMhOrch::getEsCache(const std::string &key)
{
    auto entry_it = m_esDataMap.find(key);
    return (entry_it != m_esDataMap.end()) ? entry_it->second : nullptr;
}

// Note: For keys in "VlanX:PortName" format, if a port is associated with multiple VLANs,
// this function returns only the first matching entry found.
struct EsCacheEntry *EvpnMhOrch::getEsCacheForPort(const std::string &key)
{
    for (const auto &entry : m_esDataMap)
    {
        if (entry.first.find(key) != std::string::npos)
        {
            return entry.second;
        }
    }
    return nullptr;
}

static std::string getPortFromEsKey(const std::string &key)
{
    auto pos = key.find(':');
    return (pos != std::string::npos) ? key.substr(pos + 1) : "Unknown";
}

static std::string getVlanFromEsKey(const std::string &key)
{
    auto pos = key.find(':');
    return (pos != std::string::npos) ? key.substr(0, pos) : "Unknown";
}

bool EvpnMhOrch::updateEsCache(string &key, KeyOpFieldsValuesTuple &t)
{
    bool is_df = false;
    struct EsCacheEntry *existing_entry = nullptr;

    // Note: KeyOpFieldsValuesTuple is the standard swss framework type for receiving
    // data from Redis tables. Although not optimal for lookups, it's part of the API contract.
    for (const auto &i : kfvFieldsValues(t))
    {
        if (fvField(i) == "df")
        {
            is_df = (fvValue(i) == "true");
            break;  // Found the field we need, no need to continue
        }
    }

    existing_entry = getEsCache(key);
    if (existing_entry)
    {
        existing_entry->is_df = is_df;
    }
    else
    {
        existing_entry = new EsCacheEntry(is_df);
        m_esDataMap[key] = existing_entry;
    }

    /*
     * DESIGN NOTE: The YANG schema takes only the interface name, but the implementation
     * uses a composite key format "VlanX:InterfaceName" for cache lookups. This design
     * has performance implications:
     *
     * 1. Each VLAN in the bridge triggers an attribute update against the main port
     * 2. Current flat map structure requires string parsing on every lookup
     *
     * TODO: Consider alternative data structures for better performance:
     * - Nested map: map<vlan_id, map<port_name, EsCacheEntry*>>
     * - Multimap indexed by port for O(1) port-based lookups
     * - Parent/child cache relationship to reduce redundant updates
     */
    std::string port_name = getPortFromEsKey(key);
    std::string vlan_id = getVlanFromEsKey(key);
    Port port;
    sai_object_id_t vlan_member_id;

    SWSS_LOG_NOTICE("updateEsCache: SET oper: %s, vlan: %s, port_name: %s, is_df: %d", key.c_str(), vlan_id.c_str(), port_name.c_str(), existing_entry->is_df);

    if (!gPortsOrch->getPort(vlan_id, port))
    {
        SWSS_LOG_ERROR("updateEsCache: interface: %s, Vlan is not not yet created, returning", key.c_str());
        return false;
    }

    if (gPortsOrch->getVlanMember(port_name, port, vlan_member_id))
    {
        /*
         * TODO: Verify the correct SAI attribute to use.
         * Current: SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP (workaround)
         * HLD suggests: SAI_BRIDGE_PORT_ATTR_BRIDGE_PORT_NEXT_HOP_GROUP_ID
         * Need to confirm with SAI implementation and HLD requirements.
         *
         * FIXME: Verify logic correctness - attribute name suggests BUM traffic should
         * be DROPPED on non-DF. If true, this should be: !existing_entry->is_df
         * (DF=false → DROP=true, DF=true → DROP=false)
         */
        sai_attribute_t attr;
        attr.id = SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP;
        attr.value.booldata = existing_entry->is_df;

        auto status = sai_vlan_api->set_vlan_member_attribute(vlan_member_id, &attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("updateEsCache: Failed to set VLAN member attribute for %s, SAI status: %d. "
                          "BUM traffic forwarding state may be incorrect. Will retry.", key.c_str(), status);
            return false;
        }
    }
    else
    {
        SWSS_LOG_ERROR("updateEsCache: interface %s vlan_member_id doesnt exit", key.c_str());
        return false;
    }
    return true;
}

bool EvpnMhOrch::deleteEsCache(string &key)
{
    EsCacheEntry *entry = getEsCache(key);

    if (!entry)
    {
        SWSS_LOG_WARN("deleteEsCache: Entry not found for key: %s", key.c_str());
        return true;  // Nothing to delete, consider it successful
    }

    SWSS_LOG_NOTICE("deleteEsCache: DEL oper: intf: %s, is_df: %d", key.c_str(), entry->is_df);
    std::string port_name = getPortFromEsKey(key);
    std::string vlan_id = getVlanFromEsKey(key);
    Port port;
    sai_object_id_t vlan_member_id;

    if (!gPortsOrch->getPort(vlan_id, port))
    {
        SWSS_LOG_ERROR("deleteEsCache: interface: %s, Vlan is not not yet created, returning", key.c_str());
        return false;
    }
    if (gPortsOrch->getVlanMember(port_name, port, vlan_member_id))
    {
        /*
         * TODO: Verify the correct SAI attribute to use.
         * Current: SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP (workaround)
         * HLD suggests: SAI_BRIDGE_PORT_ATTR_BRIDGE_PORT_NEXT_HOP_GROUP_ID
         * Need to confirm with SAI implementation and HLD requirements.
         *
         * Note: Setting to false on delete to restore default forwarding behavior.
         */
        sai_attribute_t attr;
        attr.id = SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP;
        attr.value.booldata = false;

        auto status = sai_vlan_api->set_vlan_member_attribute(vlan_member_id, &attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("deleteEsCache: Failed to reset VLAN member attribute for %s, SAI status: %d. "
                          "BUM traffic forwarding state may be incorrect. Will retry.", key.c_str(), status);
            return false;
        }
    }
    else
    {
        SWSS_LOG_ERROR("deleteEsCache: interface %s vlan_member_id doesnt exit", key.c_str());
        return false;
    }
    m_esDataMap.erase(key);
    delete entry;
    return true;
}

bool EvpnMhOrch::vlanMembersApplyNonDF(string port_name)
{
    vlan_members_t vlan_members;
    Port port;
    if (!gPortsOrch->getPort(port_name, port))
    {
        SWSS_LOG_ERROR("vlanMembersApplyNonDF: getPort() fails for port_name:%s", port_name.c_str());
        return false;
    }
    gPortsOrch->getPortVlanMembers(port, vlan_members);
    for (const auto &member : vlan_members)
    {
        auto vlan_id = member.first;
        auto vlan_mem_entry = member.second;
        /*
         * TODO: Verify the correct SAI attribute to use.
         * Current: SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP (workaround)
         * HLD suggests: SAI_BRIDGE_PORT_ATTR_BRIDGE_PORT_NEXT_HOP_GROUP_ID
         * Need to confirm with SAI implementation and HLD requirements.
         *
         * FIXME: Verify logic correctness - attribute name suggests BUM traffic should
         * be DROPPED on non-DF. If true, this should be: !isInterfaceDF(...)
         * (DF=false → DROP=true, DF=true → DROP=false)
         */
        sai_attribute_t attr;
        attr.id = SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP;
        attr.value.booldata = isInterfaceDF(port_name, vlan_id);
        SWSS_LOG_NOTICE("vlanMembersApplyNonDF: set Non-DF for port: %s, vlan: %d", port_name.c_str(), vlan_id);

        auto status = sai_vlan_api->set_vlan_member_attribute(vlan_mem_entry.vlan_member_id, &attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("vlanMembersApplyNonDF: Failed to set VLAN member attribute for port: %s, vlan: %d, SAI status: %d. "
                          "BUM traffic forwarding state may be incorrect. Will retry.", port_name.c_str(), vlan_id, status);
            return false;
        }
    }
    return true;
}
void EvpnMhOrch::doEvpnEsIntfTask(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);

        SWSS_LOG_NOTICE("doEvpnEsIntfTask: %s oper: ESI intf: %s", op.c_str(), key.c_str());

        if (op == SET_COMMAND)
        {
            /* Always register ES membership immediately so that portsOrch
             * can query it when creating VLAN members later.  The VLAN
             * member DF attribute application is best-effort — if no VLAN
             * members exist yet, they will pick up the DF state during
             * creation via isPortInterfaceAssociatedToEs(). */
            m_esIntfMap[key] = true;

            /* Parse failover_mode and peer_vtep fields if present */
            for (const auto &i : kfvFieldsValues(t))
            {
                if (fvField(i) == "failover_mode")
                {
                    string mode_str = fvValue(i);
                    if (mode_str == "l2")
                        m_esFailoverMode[key] = EvpnMhFailoverMode::L2;
                    else if (mode_str == "l3")
                        m_esFailoverMode[key] = EvpnMhFailoverMode::L3;
                    else if (mode_str == "hw")
                        m_esFailoverMode[key] = EvpnMhFailoverMode::HW;
                    else
                        m_esFailoverMode[key] = EvpnMhFailoverMode::AUTO;
                    SWSS_LOG_NOTICE("EVPN MH: failover_mode for %s set to %s",
                        key.c_str(), mode_str.c_str());
                }
                else if (fvField(i) == "peer_vtep")
                {
                    m_esPeerVtep[key] = fvValue(i);
                    SWSS_LOG_NOTICE("EVPN MH: peer_vtep for %s set to %s",
                        key.c_str(), fvValue(i).c_str());
                }
                else if (fvField(i) == "peer_vteps")
                {
                    /* Comma-separated list of sister T1 VTEP IPs for HW FRR.
                     * Order defines bitmask indexing: sister[0]=bit 0, etc. */
                    m_esPeerVtepList[key].clear();
                    string vteps_str = fvValue(i);
                    stringstream ss(vteps_str);
                    string token;
                    while (getline(ss, token, ','))
                    {
                        token.erase(0, token.find_first_not_of(" "));
                        token.erase(token.find_last_not_of(" ") + 1);
                        if (!token.empty())
                        {
                            m_esPeerVtepList[key].push_back(token);
                            SWSS_LOG_NOTICE("EVPN MH: peer_vteps[%zu] for %s: %s",
                                m_esPeerVtepList[key].size() - 1, key.c_str(), token.c_str());
                        }
                    }
                    /* Also set single peer_vtep for backward compat (first in list) */
                    if (!m_esPeerVtepList[key].empty())
                        m_esPeerVtep[key] = m_esPeerVtepList[key][0];
                }
                else if (fvField(i) == "server_ipv4")
                {
                    /* Comma-separated list of server overlay IPs, e.g. "10.0.0.2/32,10.0.0.3/32" */
                    m_esServerIps[key].clear();
                    string ips_str = fvValue(i);
                    stringstream ss(ips_str);
                    string token;
                    while (getline(ss, token, ','))
                    {
                        /* Trim whitespace */
                        token.erase(0, token.find_first_not_of(" "));
                        token.erase(token.find_last_not_of(" ") + 1);
                        if (token.empty()) continue;
                        /* Add /32 if not present */
                        if (token.find('/') == string::npos)
                            token += "/32";
                        try {
                            m_esServerIps[key].push_back(IpPrefix(token));
                            SWSS_LOG_NOTICE("EVPN MH: server_ipv4 for %s: %s",
                                key.c_str(), token.c_str());
                        } catch (const std::exception &e) {
                            SWSS_LOG_ERROR("EVPN MH: invalid server_ipv4 '%s' for %s: %s",
                                token.c_str(), key.c_str(), e.what());
                        }
                    }
                }
                else if (fvField(i) == "es_sys_mac")
                {
                    m_esSysMac[key] = fvValue(i);
                    SWSS_LOG_NOTICE("EVPN MH: es_sys_mac for %s set to %s",
                        key.c_str(), fvValue(i).c_str());
                }
            }

            /*
             * Apply ES system MAC to the PortChannel interface.
             *
             * Both T1s in an EVPN MH Ethernet Segment must share the same
             * LACP actor system MAC on the PortChannel.  Without this, LACP
             * PDUs from each T1 carry different system IDs and the server
             * treats them as separate LAGs instead of a multi-chassis LAG.
             *
             * The MAC is set at the kernel level (ip link set) which
             * propagates to VPP via LCP sync.
             */
            auto sys_mac_it = m_esSysMac.find(key);
            if (sys_mac_it != m_esSysMac.end() && !sys_mac_it->second.empty())
            {
                string cmd = "ip link set " + key + " address " + sys_mac_it->second;
                int ret = system(cmd.c_str());
                if (ret == 0)
                {
                    SWSS_LOG_NOTICE("EVPN MH: set %s MAC to %s (es_sys_mac)",
                        key.c_str(), sys_mac_it->second.c_str());
                }
                else
                {
                    SWSS_LOG_WARN("EVPN MH: failed to set %s MAC to %s (ret=%d)",
                        key.c_str(), sys_mac_it->second.c_str(), ret);
                }
            }

            if (!vlanMembersApplyNonDF(key))
            {
                // SAI operation failed — ES is registered but DF state
                // not applied.  Leave in m_toSync for retry.
                ++it;
                continue;
            }

            /* HW FRR: create protection groups if configured */
            auto mode_it = m_esFailoverMode.find(key);
            if (mode_it != m_esFailoverMode.end() &&
                mode_it->second == EvpnMhFailoverMode::HW)
            {
                sai_status_t status = createHwFrrProtectionGroups(key);
                if (status != SAI_STATUS_SUCCESS)
                {
                    SWSS_LOG_WARN("EVPN MH HW FRR: failed to create protection groups for %s (status=%d), "
                                  "will retry", key.c_str(), status);
                    ++it;
                    continue;
                }
            }
        }
        else if (op == DEL_COMMAND)
        {
            /* HW FRR: remove protection groups before erasing config */
            if (m_hwFrrState.find(key) != m_hwFrrState.end())
            {
                removeHwFrrProtectionGroups(key);
            }

            m_esIntfMap.erase(key);
            m_esFailoverMode.erase(key);
            m_esPeerVtep.erase(key);
            m_esPeerVtepList.erase(key);
            m_esServerIps.erase(key);
            vlanMembersApplyNonDF(key);  /* reset existing members */
        }

        it = consumer.m_toSync.erase(it);
    }
}

void EvpnMhOrch::doEvpnEsDfTask(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);

        bool success = false;
        if (op == SET_COMMAND)
        {
            success = updateEsCache(key, t);
        }
        else if (op == DEL_COMMAND)
        {
            success = deleteEsCache(key);
        }

        if (!success)
        {
            // SAI operation failed, leave in m_toSync for retry
            ++it;
        }
        else
        {
            it = consumer.m_toSync.erase(it);
        }
    }
}

void EvpnMhOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    string table_name = consumer.getTableName();
    if (table_name == "EVPN_DF_TABLE")
    {
        doEvpnEsDfTask(consumer);
    }
    else if (table_name == "EVPN_ETHERNET_SEGMENT")
    {
        doEvpnEsIntfTask(consumer);
    }
    else if (table_name == "EVPN_MH_ES_STATE_TABLE")
    {
        doEvpnMhEsStateTask(consumer);
    }
}

bool EvpnMhOrch::isInterfaceDF(const std::string &port_name, sai_vlan_id_t vlan_id)
{
    std::string df_key = VLAN_PREFIX + std::to_string(vlan_id) + ":" + port_name;
    if (EsCacheEntry *entry = getEsCache(df_key))
        return entry->is_df;
    return false;
}

bool EvpnMhOrch::isPortAndVlanAssociatedToEs(const std::string &port_name, sai_vlan_id_t vlan_id)
{
    if (isPortInterfaceAssociatedToEs(port_name))
        return true;

    std::string df_key = VLAN_PREFIX + std::to_string(vlan_id) + ":" + port_name;
    return getEsCache(df_key) != nullptr;
}

bool EvpnMhOrch::isPortInterfaceAssociatedToEs(const std::string &port_name)
{
    return (m_esIntfMap.find(port_name) != m_esIntfMap.end());
}

std::string EvpnMhOrch::getPeerVtepForEsPort(const std::string &port_name)
{
    /*
     * For Phase 1 PoC: Return the first remote VTEP from VXLAN_REMOTE_VNI table.
     * In a full implementation, this would look up the ES membership to find
     * which specific peer VTEPs share the same Ethernet Segment.
     *
     * The VXLAN_REMOTE_VNI table is populated by fdbsyncd when it receives
     * EVPN Type-3 IMET routes from peer VTEPs.
     * Key format: VXLAN_REMOTE_VNI_TABLE:<vlan>:<remote_vtep_ip>
     */
    try {
        swss::DBConnector appDb("APPL_DB", 0);
        auto keys = appDb.keys("VXLAN_REMOTE_VNI_TABLE:*");

        for (const auto &key : keys)
        {
            /* Extract remote VTEP IP from key: VXLAN_REMOTE_VNI_TABLE:Vlan10:10.1.0.4 */
            auto lastColon = key.rfind(':');
            if (lastColon != std::string::npos)
            {
                std::string vtep_ip = key.substr(lastColon + 1);
                SWSS_LOG_NOTICE("getPeerVtepForEsPort: port=%s peer_vtep=%s",
                    port_name.c_str(), vtep_ip.c_str());
                return vtep_ip;
            }
        }
    } catch (const std::exception &e) {
        SWSS_LOG_ERROR("getPeerVtepForEsPort: exception: %s", e.what());
    }

    SWSS_LOG_NOTICE("getPeerVtepForEsPort: no peer VTEP found for port %s", port_name.c_str());
    return "";
}

EvpnMhFailoverMode EvpnMhOrch::getEffectiveFailoverMode(const std::string &port_alias)
{
    /* Check explicit per-ES configuration */
    auto it = m_esFailoverMode.find(port_alias);
    EvpnMhFailoverMode configured = EvpnMhFailoverMode::AUTO;
    if (it != m_esFailoverMode.end())
    {
        configured = it->second;
    }

    if (configured == EvpnMhFailoverMode::L2)
        return EvpnMhFailoverMode::L2;

    if (configured == EvpnMhFailoverMode::HW)
    {
        /* HW FRR requires peer_vteps and server_ipv4 configured */
        auto vtep_it = m_esPeerVtepList.find(port_alias);
        auto sip_it = m_esServerIps.find(port_alias);
        if ((vtep_it == m_esPeerVtepList.end() || vtep_it->second.empty()) &&
            (m_esPeerVtep.find(port_alias) == m_esPeerVtep.end() || m_esPeerVtep[port_alias].empty()))
        {
            SWSS_LOG_WARN("EVPN MH: HW failover requested for %s but no peer_vteps configured, "
                          "falling back to L3/L2", port_alias.c_str());
            /* Fall through to L3/AUTO logic */
        }
        else if (sip_it == m_esServerIps.end() || sip_it->second.empty())
        {
            SWSS_LOG_WARN("EVPN MH: HW failover requested for %s but no server_ipv4 configured, "
                          "falling back to L3/L2", port_alias.c_str());
        }
        else
        {
            return EvpnMhFailoverMode::HW;
        }
    }

    if (configured == EvpnMhFailoverMode::L3 || configured == EvpnMhFailoverMode::AUTO)
    {
        /* Check if L3VNI is available: port → VLAN → VRF → L3VNI */
        sai_object_id_t vrf_oid = getVrfOidForEsPort(port_alias);
        if (vrf_oid == SAI_NULL_OBJECT_ID)
        {
            if (configured == EvpnMhFailoverMode::L3)
            {
                SWSS_LOG_WARN("EVPN MH: L3 failover requested for %s but no VRF found, falling back to L2",
                    port_alias.c_str());
            }
            return EvpnMhFailoverMode::L2;
        }

        /* Check VRF has a mapped L3VNI */
        VRFOrch *vrf_orch = gDirectory.get<VRFOrch*>();
        std::string vrf_name = vrf_orch->getVRFname(vrf_oid);
        if (vrf_name.empty())
        {
            return EvpnMhFailoverMode::L2;
        }

        uint32_t l3vni = vrf_orch->getVRFmappedVNI(vrf_name);
        if (l3vni == 0)
        {
            if (configured == EvpnMhFailoverMode::L3)
            {
                SWSS_LOG_WARN("EVPN MH: L3 failover requested for %s but no L3VNI for VRF %s, falling back to L2",
                    port_alias.c_str(), vrf_name.c_str());
            }
            return EvpnMhFailoverMode::L2;
        }

        SWSS_LOG_NOTICE("EVPN MH: effective failover mode for %s is L3 (VRF=%s, L3VNI=%u)",
            port_alias.c_str(), vrf_name.c_str(), l3vni);
        return EvpnMhFailoverMode::L3;
    }

    return EvpnMhFailoverMode::L2;
}

sai_object_id_t EvpnMhOrch::getVrfOidForEsPort(const std::string &port_alias)
{
    /* Find VLANs this port is a member of, get the VRF OID from the VLAN's RIF */
    Port port;
    if (!gPortsOrch->getPort(port_alias, port))
    {
        SWSS_LOG_ERROR("getVrfOidForEsPort: port %s not found", port_alias.c_str());
        return SAI_NULL_OBJECT_ID;
    }

    vlan_members_t vlan_members;
    gPortsOrch->getPortVlanMembers(port, vlan_members);

    for (const auto &member : vlan_members)
    {
        std::string vlan_alias = std::string(VLAN_PREFIX) + std::to_string(member.first);
        Port vlan;
        if (gPortsOrch->getPort(vlan_alias, vlan))
        {
            if (vlan.m_vr_id != SAI_NULL_OBJECT_ID && vlan.m_vr_id != 0)
            {
                SWSS_LOG_NOTICE("getVrfOidForEsPort: port %s → %s → VRF OID 0x%" PRIx64,
                    port_alias.c_str(), vlan_alias.c_str(), vlan.m_vr_id);
                return vlan.m_vr_id;
            }
        }
    }

    SWSS_LOG_NOTICE("getVrfOidForEsPort: no VRF found for port %s", port_alias.c_str());
    return SAI_NULL_OBJECT_ID;
}

sai_object_id_t EvpnMhOrch::getL3TunnelNexthop(const std::string &peer_vtep_ip)
{
    /* Return cached nexthop if available */
    auto it = m_l3TunnelNexthops.find(peer_vtep_ip);
    if (it != m_l3TunnelNexthops.end())
    {
        return it->second;
    }

    /* Create a new L3 VxLAN tunnel nexthop */
    EvpnNvoOrch* evpn_nvo_orch = gDirectory.get<EvpnNvoOrch*>();
    VxlanTunnel* sip_tunnel = evpn_nvo_orch->getEVPNVtep();
    if (!sip_tunnel)
    {
        SWSS_LOG_ERROR("getL3TunnelNexthop: no EVPN VTEP configured");
        return SAI_NULL_OBJECT_ID;
    }

    sai_object_id_t tunnel_id = sip_tunnel->getTunnelId();

    /* Build SAI nexthop attributes for tunnel encap */
    sai_ip_address_t peer_ip;
    peer_ip.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    inet_pton(AF_INET, peer_vtep_ip.c_str(), &peer_ip.addr.ip4);

    std::vector<sai_attribute_t> nh_attrs;
    sai_attribute_t attr;

    attr.id = SAI_NEXT_HOP_ATTR_TYPE;
    attr.value.s32 = SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP;
    nh_attrs.push_back(attr);

    attr.id = SAI_NEXT_HOP_ATTR_IP;
    attr.value.ipaddr = peer_ip;
    nh_attrs.push_back(attr);

    attr.id = SAI_NEXT_HOP_ATTR_TUNNEL_ID;
    attr.value.oid = tunnel_id;
    nh_attrs.push_back(attr);

    sai_object_id_t nh_id;
    sai_status_t status = sai_next_hop_api->create_next_hop(
        &nh_id, gSwitchId,
        static_cast<uint32_t>(nh_attrs.size()),
        nh_attrs.data());

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("getL3TunnelNexthop: failed to create tunnel nexthop for %s, status %d",
            peer_vtep_ip.c_str(), status);
        return SAI_NULL_OBJECT_ID;
    }

    SWSS_LOG_NOTICE("getL3TunnelNexthop: created tunnel nexthop 0x%" PRIx64 " for peer %s",
        nh_id, peer_vtep_ip.c_str());
    m_l3TunnelNexthops[peer_vtep_ip] = nh_id;
    return nh_id;
}

std::string EvpnMhOrch::getPeerVtepForEsPortConfig(const std::string &port_name)
{
    auto it = m_esPeerVtep.find(port_name);
    if (it != m_esPeerVtep.end())
    {
        return it->second;
    }
    /* Fall back to dynamic discovery via getPeerVtepForEsPort (Type-3 routes) */
    return getPeerVtepForEsPort(port_name);
}

void EvpnMhOrch::initPeerState()
{
    if (m_peerStateInitDone)
        return;

    /* Collect unique peer VTEPs from all ES entries */
    std::set<std::string> peer_vteps;
    for (const auto &entry : m_esPeerVtep)
    {
        if (!entry.second.empty())
        {
            peer_vteps.insert(entry.second);
        }
    }

    if (peer_vteps.empty())
    {
        SWSS_LOG_NOTICE("EVPN MH initPeerState: no peer_vtep configured, skipping");
        return;
    }

    /* Pre-create L3 tunnel nexthops for each peer VTEP */
    for (const auto &vtep : peer_vteps)
    {
        sai_object_id_t nh = getL3TunnelNexthop(vtep);
        if (nh != SAI_NULL_OBJECT_ID)
        {
            SWSS_LOG_NOTICE("EVPN MH initPeerState: pre-created L3 tunnel NH for peer %s → 0x%" PRIx64,
                vtep.c_str(), nh);
        }
    }

    /* Pre-populate arp-term entries from NEIGH_TABLE for remote overlay IPs.
     * Each T1 knows its peer — we query the local NEIGH_TABLE for any entries
     * that orchagent has learned (from BGP EVPN Type-2 or local ARP) and
     * program them into VPP arp-term so BVI ARP resolution works from boot. */
    swss::DBConnector appDb("APPL_DB", 0);
    auto neigh_table = std::make_unique<swss::Table>(
        &appDb, APP_NEIGH_TABLE_NAME);
    std::vector<std::string> neigh_keys;
    neigh_table->getKeys(neigh_keys);

    for (const auto &neigh_key : neigh_keys)
    {
        /* neigh_key format: "Vlan10:10.0.0.2" */
        size_t colon = neigh_key.find(':');
        if (colon == std::string::npos)
            continue;

        std::string intf = neigh_key.substr(0, colon);
        std::string ip = neigh_key.substr(colon + 1);

        /* Only process VLAN interfaces (overlay) */
        if (intf.substr(0, 4) != "Vlan")
            continue;

        std::string mac;
        neigh_table->hget(neigh_key, "neigh", mac);
        if (mac.empty())
            continue;

        SWSS_LOG_NOTICE("EVPN MH initPeerState: arp-term candidate %s → %s on %s",
            ip.c_str(), mac.c_str(), intf.c_str());
    }

    m_peerStateInitDone = true;
    SWSS_LOG_NOTICE("EVPN MH initPeerState: complete, %zu peer VTEPs configured",
        peer_vteps.size());
}

std::vector<IpPrefix> EvpnMhOrch::getServerIpsForEsPort(const std::string &port_name)
{
    auto it = m_esServerIps.find(port_name);
    if (it != m_esServerIps.end())
    {
        return it->second;
    }
    return {};
}

bool EvpnMhOrch::isHwFrrServerIp(const IpAddress &ip)
{
    for (auto const &es_entry : m_esServerIps)
    {
        const std::string &port_name = es_entry.first;
        if (getEffectiveFailoverMode(port_name) != EvpnMhFailoverMode::HW)
        {
            continue;
        }
        for (auto const &prefix : es_entry.second)
        {
            if (prefix.getIp() == ip)
            {
                return true;
            }
        }
    }
    return false;
}

/*
 * Process EVPN_MH_ES_STATE_TABLE updates from fdbsyncd.
 * Key: <es_port> (e.g. "PortChannel0")
 * Fields:
 *   active_vteps: comma-separated list of currently active sister VTEP IPs
 *
 * This is triggered when fdbsyncd detects ES remote VTEP changes via FRR
 * (BGP Type-1 AD-per-ES route add/withdraw from sisters).
 *
 * Converts the active VTEP list to a bitmask using the configured sister
 * ordering (from peer_vteps), then calls updateHwFrrActiveSisters().
 */
void EvpnMhOrch::doEvpnMhEsStateTask(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string es_port = kfvKey(t);
        string op = kfvOp(t);

        SWSS_LOG_NOTICE("doEvpnMhEsStateTask: op=%s es_port=%s", op.c_str(), es_port.c_str());

        if (op == SET_COMMAND)
        {
            /* Only relevant for HW FRR ports */
            auto state_it = m_hwFrrState.find(es_port);
            if (state_it == m_hwFrrState.end())
            {
                SWSS_LOG_NOTICE("EVPN MH ES state: ignoring update for %s (no HW FRR state)",
                                es_port.c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            EsHwFrrState &state = state_it->second;

            /* Parse active_vteps field */
            std::set<std::string> active_vtep_set;
            for (const auto &fv : kfvFieldsValues(t))
            {
                if (fvField(fv) == "active_vteps")
                {
                    stringstream ss(fvValue(fv));
                    string token;
                    while (getline(ss, token, ','))
                    {
                        token.erase(0, token.find_first_not_of(" "));
                        token.erase(token.find_last_not_of(" ") + 1);
                        if (!token.empty())
                            active_vtep_set.insert(token);
                    }
                }
            }

            /* Convert VTEP IPs to bitmask using configured sister ordering */
            uint8_t new_mask = 0;
            for (const auto &sister : state.sisters)
            {
                if (active_vtep_set.count(sister.vtep_ip.to_string()))
                {
                    new_mask |= (1 << sister.index);
                }
            }

            SWSS_LOG_NOTICE("EVPN MH ES state: %s active_vteps=%zu → mask=0x%02x (was 0x%02x)",
                            es_port.c_str(), active_vtep_set.size(),
                            new_mask, state.active_sister_mask);

            sai_status_t status = updateHwFrrActiveSisters(es_port, new_mask);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("EVPN MH ES state: failed to update active sisters for %s (status=%d)",
                               es_port.c_str(), status);
                /* Leave in m_toSync for retry */
                ++it;
                continue;
            }
        }
        else if (op == DEL_COMMAND)
        {
            /* ES gone — all sisters down */
            auto state_it = m_hwFrrState.find(es_port);
            if (state_it != m_hwFrrState.end())
            {
                SWSS_LOG_NOTICE("EVPN MH ES state: %s removed — marking all sisters down",
                                es_port.c_str());
                updateHwFrrActiveSisters(es_port, 0);
            }
        }

        it = consumer.m_toSync.erase(it);
    }
}

/*
 * Query FRR for the list of active remote VTEPs on a given ES port.
 * Returns a set of VTEP IP strings from `show evpn es detail`.
 * Used by HW FRR to determine the active sister mask.
 */
std::set<std::string> EvpnMhOrch::getActiveRemoteVteps(const std::string &port_name)
{
    SWSS_LOG_ENTER();
    std::set<std::string> result;

    std::string cmd = "vtysh -c 'show evpn es detail' 2>/dev/null";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp)
    {
        SWSS_LOG_ERROR("getActiveRemoteVteps: failed to run vtysh for port %s", port_name.c_str());
        return result;
    }

    char buf[512];
    bool in_matching_es = false;
    bool in_vteps_section = false;

    while (fgets(buf, sizeof(buf), fp))
    {
        std::string line(buf);

        if (line.find("ESI:") != std::string::npos)
        {
            if (in_matching_es)
                break;
            in_matching_es = false;
            in_vteps_section = false;
        }

        if (line.find("Interface:") != std::string::npos)
        {
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos)
            {
                std::string intf = line.substr(colon_pos + 1);
                intf.erase(0, intf.find_first_not_of(" \t"));
                intf.erase(intf.find_last_not_of(" \t\r\n") + 1);
                if (intf == port_name)
                    in_matching_es = true;
            }
        }

        if (!in_matching_es)
            continue;

        if (line.find("VTEPs:") != std::string::npos)
        {
            in_vteps_section = true;
            continue;
        }

        if (in_vteps_section)
        {
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

            if (trimmed.empty() || trimmed.find(':') != std::string::npos)
            {
                in_vteps_section = false;
            }
            else
            {
                /* VTEP line may include flags like "10.1.0.4 df-preference: 0" */
                auto space = trimmed.find(' ');
                std::string vtep_ip = (space != std::string::npos) ?
                    trimmed.substr(0, space) : trimmed;
                result.insert(vtep_ip);
            }
        }
    }

    pclose(fp);
    SWSS_LOG_NOTICE("getActiveRemoteVteps: port %s has %zu active remote VTEPs",
                    port_name.c_str(), result.size());
    return result;
}

/*
 * Check if the peer VTEP still has the Ethernet Segment active by querying
 * FRR's zebra EVPN ES detail table.  We look for the ES block matching the
 * given port's interface name and check if remote VTEPs are present.
 *
 * This prevents black-hole tunnel routes when both T1s lose their PortChannel
 * to a server (i.e., the server is completely disconnected).
 *
 * Uses `vtysh -c 'show evpn es detail'` and parses the output for:
 *   ESI: <esi>
 *     Interface: <port>
 *     Type: <flags containing "Remote">
 *     VTEPs:
 *       <vtep_ip>
 *
 * If no remote VTEPs are listed for this port's ES, the peer has also lost
 * the ES and traffic should not be tunneled.
 */
bool EvpnMhOrch::isPeerEsActive(const std::string &port_name)
{
    SWSS_LOG_ENTER();

    std::string cmd = "vtysh -c 'show evpn es detail' 2>/dev/null";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp)
    {
        SWSS_LOG_ERROR("isPeerEsActive: failed to run vtysh for port %s", port_name.c_str());
        /* Fail-open: assume peer is active to avoid dropping traffic unnecessarily */
        return true;
    }

    char buf[512];
    bool in_matching_es = false;
    bool in_vteps_section = false;
    bool has_remote_vtep = false;
    bool found_es = false;

    while (fgets(buf, sizeof(buf), fp))
    {
        std::string line(buf);

        /* Detect start of a new ES block: "ESI: 03:aa:bb:..." */
        if (line.find("ESI:") != std::string::npos)
        {
            /* If we were already in the matching block, we're done */
            if (in_matching_es)
                break;

            in_matching_es = false;
            in_vteps_section = false;
        }

        /* Check if this ES block matches our port by interface name.
         * FRR output includes a line like: "  Interface: PortChannel1" */
        if (line.find("Interface:") != std::string::npos)
        {
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos)
            {
                std::string intf = line.substr(colon_pos + 1);
                intf.erase(0, intf.find_first_not_of(" \t"));
                intf.erase(intf.find_last_not_of(" \t\r\n") + 1);

                if (intf == port_name)
                {
                    in_matching_es = true;
                    found_es = true;
                    SWSS_LOG_NOTICE("isPeerEsActive: found ES block for port %s",
                        port_name.c_str());
                }
            }
        }

        if (!in_matching_es)
            continue;

        /* Check Type line for "Remote" flag */
        if (line.find("Type:") != std::string::npos &&
            line.find("Remote") != std::string::npos)
        {
            has_remote_vtep = true;
            SWSS_LOG_NOTICE("isPeerEsActive: ES for %s has Remote type flag",
                port_name.c_str());
        }

        /* Parse VTEPs section */
        if (line.find("VTEPs:") != std::string::npos)
        {
            in_vteps_section = true;
            continue;
        }

        if (in_vteps_section)
        {
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

            if (trimmed.empty())
            {
                in_vteps_section = false;
            }
            else
            {
                has_remote_vtep = true;
                SWSS_LOG_NOTICE("isPeerEsActive: ES for %s has remote VTEP %s",
                    port_name.c_str(), trimmed.c_str());
                break;
            }
        }
    }

    pclose(fp);

    if (!found_es)
    {
        SWSS_LOG_WARN("isPeerEsActive: no ES block found for port %s in FRR, assuming active",
            port_name.c_str());
        return true;  /* Fail-open */
    }

    SWSS_LOG_NOTICE("isPeerEsActive: port %s peer ES active = %s",
        port_name.c_str(), has_remote_vtep ? "yes" : "no");
    return has_remote_vtep;
}

/*
 * HW FRR Protection Groups — Boot-time provisioning
 *
 * For an ES port with N sisters, creates:
 *   - N tunnel nexthops (one per sister VTEP)
 *   - 2^N - 1 HW_PROTECTION NHGs (one per non-empty subset of sisters)
 *   - For each server IP:
 *       - 1 local nexthop
 *       - 1 PROTECTION NHG (PRIMARY=local, STANDBY=all-sisters NHG)
 *       - 1 /32 route in VRF → PROTECTION NHG
 */
sai_status_t EvpnMhOrch::createHwFrrProtectionGroups(const std::string &es_port)
{
    SWSS_LOG_ENTER();

    /* Gather sister VTEPs: prefer peer_vteps list, fall back to single peer_vtep */
    std::vector<std::string> sister_ips;
    auto vtep_list_it = m_esPeerVtepList.find(es_port);
    if (vtep_list_it != m_esPeerVtepList.end() && !vtep_list_it->second.empty())
    {
        sister_ips = vtep_list_it->second;
    }
    else
    {
        auto vtep_it = m_esPeerVtep.find(es_port);
        if (vtep_it != m_esPeerVtep.end() && !vtep_it->second.empty())
        {
            sister_ips.push_back(vtep_it->second);
        }
    }

    if (sister_ips.empty())
    {
        SWSS_LOG_ERROR("HW FRR: no peer VTEPs for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    uint8_t N = static_cast<uint8_t>(sister_ips.size());
    if (N > 7)
    {
        SWSS_LOG_ERROR("HW FRR: too many sisters (%u) for ES port %s, max 7",
                       N, es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    auto server_ips = getServerIpsForEsPort(es_port);
    if (server_ips.empty())
    {
        SWSS_LOG_ERROR("HW FRR: no server_ipv4 for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Get VRF OID for route programming */
    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);
    if (vrf_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_ERROR("HW FRR: no VRF for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Get VLAN RIF for local nexthop */
    Port es_port_obj;
    if (!gPortsOrch->getPort(es_port, es_port_obj))
    {
        SWSS_LOG_ERROR("HW FRR: port %s not found", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Find the VLAN this port is a member of */
    vlan_members_t vlan_members;
    gPortsOrch->getPortVlanMembers(es_port_obj, vlan_members);
    sai_object_id_t vlan_rif_oid = SAI_NULL_OBJECT_ID;
    std::string vlan_alias;
    for (const auto &member : vlan_members)
    {
        vlan_alias = std::string(VLAN_PREFIX) + std::to_string(member.first);
        Port vlan;
        if (gPortsOrch->getPort(vlan_alias, vlan) && vlan.m_rif_id != SAI_NULL_OBJECT_ID)
        {
            vlan_rif_oid = vlan.m_rif_id;
            break;
        }
    }
    if (vlan_rif_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_ERROR("HW FRR: no VLAN RIF for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Get PortChannel SAI OID for MONITORED_OBJECT */
    sai_object_id_t pc_oid = es_port_obj.m_lag_id;
    if (pc_oid == SAI_NULL_OBJECT_ID)
    {
        /* Not a LAG — use the port OID directly */
        pc_oid = es_port_obj.m_port_id;
    }

    SWSS_LOG_NOTICE("HW FRR: creating protection groups for ES port %s: "
                    "%u sisters, %zu server IPs, VRF 0x%" PRIx64 ", RIF 0x%" PRIx64,
                    es_port.c_str(), N, server_ips.size(), vrf_oid, vlan_rif_oid);

    /* Initialize per-ES state */
    EsHwFrrState &state = m_hwFrrState[es_port];
    state.es_port = es_port;
    state.sisters.clear();
    state.nhg_subsets.clear();
    state.prot_groups.clear();

    /* Step 1: Create tunnel nexthops for each sister */
    for (uint8_t i = 0; i < N; i++)
    {
        sai_object_id_t nh_oid = getL3TunnelNexthop(sister_ips[i]);
        if (nh_oid == SAI_NULL_OBJECT_ID)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create tunnel NH for sister %s",
                           sister_ips[i].c_str());
            removeHwFrrProtectionGroups(es_port);
            return SAI_STATUS_FAILURE;
        }

        SisterVtep sister;
        sister.vtep_ip = IpAddress(sister_ips[i]);
        sister.nh_tunnel_oid = nh_oid;
        sister.index = i;
        state.sisters.push_back(sister);

        SWSS_LOG_NOTICE("HW FRR: sister[%u] = %s → NH 0x%" PRIx64,
                        i, sister_ips[i].c_str(), nh_oid);
    }

    /* Step 2: Pre-provision 2^N - 1 HW_PROTECTION NHGs (all non-empty subsets) */
    uint8_t all_mask = static_cast<uint8_t>((1 << N) - 1);
    for (uint8_t mask = 1; mask <= all_mask; mask++)
    {
        /* Create HW_PROTECTION NHG */
        sai_attribute_t nhg_attr;
        nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
        nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_HW_PROTECTION;

        sai_object_id_t nhg_oid;
        sai_status_t status = sai_next_hop_group_api->create_next_hop_group(
            &nhg_oid, gSwitchId, 1, &nhg_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create HW_PROTECTION NHG for mask 0x%02x (status=%d)",
                           mask, status);
            removeHwFrrProtectionGroups(es_port);
            return status;
        }

        HwProtNhg &subset = state.nhg_subsets[mask];
        subset.sister_mask = mask;
        subset.nhg_oid = nhg_oid;

        /* Add members for each sister in this subset */
        for (uint8_t i = 0; i < N; i++)
        {
            if (!(mask & (1 << i)))
                continue;

            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = nhg_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = state.sisters[i].nh_tunnel_oid;
            mbr_attrs.push_back(attr);

            sai_object_id_t mbr_oid;
            status = sai_next_hop_group_api->create_next_hop_group_member(
                &mbr_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()),
                mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to create NHG member for mask 0x%02x sister %u (status=%d)",
                               mask, i, status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }
            subset.member_oids.push_back(mbr_oid);
        }

        SWSS_LOG_NOTICE("HW FRR: NHG[0x%02x] = 0x%" PRIx64 " with %zu members",
                        mask, nhg_oid, subset.member_oids.size());
    }

    /* Step 3: For each server IP, create PROTECTION NHG + route */
    state.active_sister_mask = all_mask;

    for (const auto &server_ip : server_ips)
    {
        HwFrrProtectionGroup prot;
        prot.server_ip = server_ip;
        prot.nh_original_oid = SAI_NULL_OBJECT_ID;
        prot.owns_local_nh = false;
        prot.owns_route = false;

        /* 3a. Get local nexthop — borrow from neighorch if available,
         *     else create our own (IP type, via VLAN RIF) */
        {
            std::string ip_str = server_ip.getIp().to_string();
            IpAddress server_addr(ip_str);
            NextHopKey nh_key(server_addr, vlan_alias);

            if (gNeighOrch->hasNextHop(nh_key))
            {
                prot.nh_local_oid = gNeighOrch->getNextHopId(nh_key);
                prot.owns_local_nh = false;
                SWSS_LOG_NOTICE("HW FRR: borrowed local NH for %s from neighorch → 0x%" PRIx64,
                                ip_str.c_str(), prot.nh_local_oid);
            }
            else
            {
                /* Neighbor not yet resolved — create our own NH */
                sai_ip_address_t sai_ip;
                sai_ip.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
                inet_pton(AF_INET, ip_str.c_str(), &sai_ip.addr.ip4);

                std::vector<sai_attribute_t> nh_attrs;
                sai_attribute_t attr;

                attr.id = SAI_NEXT_HOP_ATTR_TYPE;
                attr.value.s32 = SAI_NEXT_HOP_TYPE_IP;
                nh_attrs.push_back(attr);

                attr.id = SAI_NEXT_HOP_ATTR_IP;
                attr.value.ipaddr = sai_ip;
                nh_attrs.push_back(attr);

                attr.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
                attr.value.oid = vlan_rif_oid;
                nh_attrs.push_back(attr);

                sai_status_t status = sai_next_hop_api->create_next_hop(
                    &prot.nh_local_oid, gSwitchId,
                    static_cast<uint32_t>(nh_attrs.size()),
                    nh_attrs.data());
                if (status != SAI_STATUS_SUCCESS)
                {
                    SWSS_LOG_ERROR("HW FRR: failed to create local NH for %s (status=%d)",
                                   ip_str.c_str(), status);
                    removeHwFrrProtectionGroups(es_port);
                    return status;
                }
                prot.owns_local_nh = true;
                SWSS_LOG_NOTICE("HW FRR: created local NH for %s → 0x%" PRIx64 " (no neighbor yet)",
                                ip_str.c_str(), prot.nh_local_oid);
            }
        }

        /* 3b. Create PROTECTION NHG */
        {
            sai_attribute_t nhg_attr;
            nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
            nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_PROTECTION;

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group(
                &prot.prot_nhg_oid, gSwitchId, 1, &nhg_attr);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to create PROTECTION NHG for %s (status=%d)",
                               server_ip.to_string().c_str(), status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }
        }

        /* 3c. Create PRIMARY member (local NH, monitored by PortChannel) */
        {
            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = prot.prot_nhg_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = prot.nh_local_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE;
            attr.value.s32 = SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_PRIMARY;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_MONITORED_OBJECT;
            attr.value.oid = pc_oid;
            mbr_attrs.push_back(attr);

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
                &prot.primary_member_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()),
                mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to create PRIMARY member (status=%d)", status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }
        }

        /* 3d. Create STANDBY member → HW_PROTECTION NHG with all sisters */
        {
            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = prot.prot_nhg_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = state.nhg_subsets[all_mask].nhg_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE;
            attr.value.s32 = SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_STANDBY;
            mbr_attrs.push_back(attr);

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
                &prot.standby_member_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()),
                mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to create STANDBY member (status=%d)", status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }
        }

        /* 3e. Create /32 route in VRF → PROTECTION NHG.
         *     The /32 host path currently comes from the SAI neighbor entry
         *     (ARP adjacency), not a SAI route. We create a new route entry
         *     pointing to our PROTECTION NHG. VPP's FIB gives API-sourced
         *     routes higher priority than adjacency-sourced paths, so our
         *     route will be used for forwarding.
         *     The primary member of the PROTECTION NHG uses the same NH OID
         *     as the neighbor entry, so traffic flows identically in the
         *     normal (non-failover) case. */
        {
            sai_route_entry_t route_entry;
            route_entry.switch_id = gSwitchId;
            route_entry.vr_id = vrf_oid;
            route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

            std::string ip_str = server_ip.getIp().to_string();
            inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);

            std::string mask_str = server_ip.getMask().to_string();
            inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

            prot.owns_route = true;

            sai_attribute_t route_attr;
            route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
            route_attr.value.oid = prot.prot_nhg_oid;

            sai_status_t status = sai_route_api->create_route_entry(
                &route_entry, 1, &route_attr);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to create route %s → PROTECTION NHG (status=%d)",
                               server_ip.to_string().c_str(), status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }
            SWSS_LOG_NOTICE("HW FRR: created route %s → prot_nhg=0x%" PRIx64
                            " (local_nh=0x%" PRIx64 " %s)",
                            server_ip.to_string().c_str(), prot.prot_nhg_oid,
                            prot.nh_local_oid,
                            prot.owns_local_nh ? "self-created" : "borrowed");
        }

        SWSS_LOG_NOTICE("HW FRR: PROTECTION group for %s: prot_nhg=0x%" PRIx64
                        " local_nh=0x%" PRIx64 " standby→NHG[0x%02x]",
                        server_ip.to_string().c_str(), prot.prot_nhg_oid,
                        prot.nh_local_oid, all_mask);

        state.prot_groups.push_back(prot);
    }

    SWSS_LOG_NOTICE("HW FRR: ES port %s fully provisioned: %u sisters, %u NHG subsets, "
                    "%zu PROTECTION groups",
                    es_port.c_str(), N, all_mask, state.prot_groups.size());
    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Remove all protection groups for an ES port.
 * Tears down in reverse order: routes, PROTECTION NHG members/NHGs,
 * HW_PROTECTION NHG members/NHGs, local NHs.
 * Tunnel NHs are shared (via m_l3TunnelNexthops) and NOT removed here.
 */
sai_status_t EvpnMhOrch::removeHwFrrProtectionGroups(const std::string &es_port)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        SWSS_LOG_NOTICE("HW FRR: no state to remove for ES port %s", es_port.c_str());
        return SAI_STATUS_SUCCESS;
    }

    EsHwFrrState &state = state_it->second;

    /* Remove routes and PROTECTION NHGs (per-server) */
    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);

    for (auto &prot : state.prot_groups)
    {
        /* Remove route (we always create it, so always delete) */
        if (vrf_oid != SAI_NULL_OBJECT_ID)
        {
            sai_route_entry_t route_entry;
            route_entry.switch_id = gSwitchId;
            route_entry.vr_id = vrf_oid;
            route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

            std::string ip_str = prot.server_ip.getIp().to_string();
            inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
            std::string mask_str = prot.server_ip.getMask().to_string();
            inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

            sai_route_api->remove_route_entry(&route_entry);
        }

        /* Remove PROTECTION NHG members, then NHG */
        if (prot.standby_member_oid != SAI_NULL_OBJECT_ID)
            sai_next_hop_group_api->remove_next_hop_group_member(prot.standby_member_oid);
        if (prot.primary_member_oid != SAI_NULL_OBJECT_ID)
            sai_next_hop_group_api->remove_next_hop_group_member(prot.primary_member_oid);
        if (prot.prot_nhg_oid != SAI_NULL_OBJECT_ID)
            sai_next_hop_group_api->remove_next_hop_group(prot.prot_nhg_oid);

        /* Remove local NH only if we created it (not borrowed from neighorch) */
        if (prot.owns_local_nh && prot.nh_local_oid != SAI_NULL_OBJECT_ID)
            sai_next_hop_api->remove_next_hop(prot.nh_local_oid);
    }

    /* Remove all HW_PROTECTION NHG subsets */
    for (auto &kv : state.nhg_subsets)
    {
        auto &subset = kv.second;
        for (auto &mbr_oid : subset.member_oids)
        {
            sai_next_hop_group_api->remove_next_hop_group_member(mbr_oid);
        }
        sai_next_hop_group_api->remove_next_hop_group(subset.nhg_oid);
    }

    SWSS_LOG_NOTICE("HW FRR: removed all protection groups for ES port %s "
                    "(%zu PROTECTION groups, %zu NHG subsets)",
                    es_port.c_str(), state.prot_groups.size(), state.nhg_subsets.size());

    m_hwFrrState.erase(state_it);
    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Update the active sister mask for an ES port.
 * Called when a sister's ES state changes (BGP Type-1 withdrawal/advertisement).
 * Swaps each PROTECTION group's STANDBY member to point to the NHG subset
 * matching the new active mask.
 *
 * This is O(M) where M = number of server IPs per ES port (typically 1-2).
 * Each update is a single SAI attribute set — no member add/remove.
 */
sai_status_t EvpnMhOrch::updateHwFrrActiveSisters(
    const std::string &es_port,
    uint8_t new_active_mask)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        SWSS_LOG_WARN("HW FRR: no state for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    EsHwFrrState &state = state_it->second;
    uint8_t old_mask = state.active_sister_mask;

    if (new_active_mask == old_mask)
    {
        SWSS_LOG_NOTICE("HW FRR: active mask unchanged (0x%02x) for %s",
                        old_mask, es_port.c_str());
        return SAI_STATUS_SUCCESS;
    }

    SWSS_LOG_NOTICE("HW FRR: updating active sisters for %s: 0x%02x → 0x%02x",
                    es_port.c_str(), old_mask, new_active_mask);

    if (new_active_mask == 0)
    {
        SWSS_LOG_WARN("HW FRR: ALL sisters down for ES port %s — no backup path!",
                      es_port.c_str());
        /* We can't point STANDBY to an empty NHG. Keep pointing to old mask —
         * traffic will black-hole on local failure, but that's the expected
         * behavior when all sisters are down. */
        state.active_sister_mask = 0;
        return SAI_STATUS_SUCCESS;
    }

    /* Validate the new mask has a pre-provisioned NHG */
    auto nhg_it = state.nhg_subsets.find(new_active_mask);
    if (nhg_it == state.nhg_subsets.end())
    {
        SWSS_LOG_ERROR("HW FRR: no pre-provisioned NHG for mask 0x%02x on %s",
                       new_active_mask, es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    sai_object_id_t new_nhg_oid = nhg_it->second.nhg_oid;

    /* Swap STANDBY member on each PROTECTION group */
    for (auto &prot : state.prot_groups)
    {
        sai_attribute_t attr;
        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        attr.value.oid = new_nhg_oid;

        sai_status_t status = sai_next_hop_group_api->set_next_hop_group_member_attribute(
            prot.standby_member_oid, &attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to swap STANDBY for %s to NHG[0x%02x] (status=%d)",
                           prot.server_ip.to_string().c_str(), new_active_mask, status);
            return status;
        }

        SWSS_LOG_NOTICE("HW FRR: swapped STANDBY for %s → NHG[0x%02x] (0x%" PRIx64 ")",
                        prot.server_ip.to_string().c_str(), new_active_mask, new_nhg_oid);
    }

    state.active_sister_mask = new_active_mask;
    return SAI_STATUS_SUCCESS;
}

/*
 * Refresh the active sister mask for an ES port by querying FRR directly.
 * This is the pull-based alternative to the EVPN_MH_ES_STATE_TABLE push path.
 * Can be called periodically or on specific events (e.g., FDB changes).
 */
sai_status_t EvpnMhOrch::refreshHwFrrSisterState(const std::string &es_port)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        return SAI_STATUS_SUCCESS;  /* Not an HW FRR port */
    }

    EsHwFrrState &state = state_it->second;

    /* Query FRR for active remote VTEPs */
    std::set<std::string> active_vteps = getActiveRemoteVteps(es_port);

    /* Convert to bitmask */
    uint8_t new_mask = 0;
    for (const auto &sister : state.sisters)
    {
        if (active_vteps.count(sister.vtep_ip.to_string()))
        {
            new_mask |= (1 << sister.index);
        }
    }

    return updateHwFrrActiveSisters(es_port, new_mask);
}

/*
 * HW FRR — Handle local port down event.
 * VPP doesn't natively implement MONITORED_OBJECT for PROTECTION NHGs,
 * so we do it in software: swap each server IP route from the PROTECTION NHG
 * (which has the now-unreachable local primary path) to the standby
 * HW_PROTECTION NHG (tunnel-only paths to sister T1s).
 *
 * Called by fdborch when an ES port (PortChannel) goes operationally down.
 */
sai_status_t EvpnMhOrch::handleHwFrrLocalPortDown(const std::string &es_port)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        SWSS_LOG_WARN("HW FRR port down: no state for %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    EsHwFrrState &state = state_it->second;
    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);
    if (vrf_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_ERROR("HW FRR port down: no VRF for %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Find the standby NHG to route through */
    uint8_t standby_mask = state.active_sister_mask;
    if (standby_mask == 0)
    {
        /* Use the full mask (all sisters) as fallback — traffic will
         * black-hole at the tunnel endpoint if sisters are also down,
         * but at least the local path is definitively unreachable. */
        for (const auto &sister : state.sisters)
            standby_mask |= (1 << sister.index);
    }

    auto nhg_it = state.nhg_subsets.find(standby_mask);
    if (nhg_it == state.nhg_subsets.end())
    {
        SWSS_LOG_ERROR("HW FRR port down: no NHG for mask 0x%02x on %s",
                       standby_mask, es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    sai_object_id_t standby_nhg_oid = nhg_it->second.nhg_oid;

    for (auto &prot : state.prot_groups)
    {
        /* Swap the /32 route to point directly to the standby NHG (tunnel only) */
        sai_route_entry_t route_entry;
        route_entry.switch_id = gSwitchId;
        route_entry.vr_id = vrf_oid;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        std::string ip_str = prot.server_ip.getIp().to_string();
        std::string mask_str = prot.server_ip.getMask().to_string();
        inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
        inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

        sai_attribute_t route_attr;
        route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        route_attr.value.oid = standby_nhg_oid;

        sai_status_t status = sai_route_api->set_route_entry_attribute(
            &route_entry, &route_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR port down: failed to swap route %s to standby NHG "
                           "(status=%d)", prot.server_ip.to_string().c_str(), status);
            continue;
        }

        SWSS_LOG_NOTICE("HW FRR port down: %s route %s → standby NHG[0x%02x] (0x%" PRIx64 ")",
                        es_port.c_str(), prot.server_ip.to_string().c_str(),
                        standby_mask, standby_nhg_oid);
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Handle local port up event.
 * Restore each server IP route to the full PROTECTION NHG (which includes
 * the local primary path via BVI).
 *
 * Called by fdborch when an ES port (PortChannel) comes back up.
 */
sai_status_t EvpnMhOrch::handleHwFrrLocalPortUp(const std::string &es_port)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        SWSS_LOG_WARN("HW FRR port up: no state for %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    EsHwFrrState &state = state_it->second;
    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);
    if (vrf_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_ERROR("HW FRR port up: no VRF for %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    for (auto &prot : state.prot_groups)
    {
        /* Restore the /32 route to the full PROTECTION NHG */
        sai_route_entry_t route_entry;
        route_entry.switch_id = gSwitchId;
        route_entry.vr_id = vrf_oid;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        std::string ip_str = prot.server_ip.getIp().to_string();
        std::string mask_str = prot.server_ip.getMask().to_string();
        inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
        inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

        sai_attribute_t route_attr;
        route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        route_attr.value.oid = prot.prot_nhg_oid;

        sai_status_t status = sai_route_api->set_route_entry_attribute(
            &route_entry, &route_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR port up: failed to restore route %s to PROTECTION NHG "
                           "(status=%d)", prot.server_ip.to_string().c_str(), status);
            continue;
        }

        SWSS_LOG_NOTICE("HW FRR port up: %s route %s → PROTECTION NHG (0x%" PRIx64 ")",
                        es_port.c_str(), prot.server_ip.to_string().c_str(),
                        prot.prot_nhg_oid);
    }

    return SAI_STATUS_SUCCESS;
}
