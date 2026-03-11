#include "evpnmhorch.h"

#include <inttypes.h>
#include <arpa/inet.h>
#include <set>
#include <sstream>

#include "portsorch.h"
#include "neighorch.h"
#include "intfsorch.h"
#include "directory.h"
#include "vxlanorch.h"
#include "vrforch.h"
#include "fdborch.h"
#include "schema.h"
#include "dbconnector.h"

extern FdbOrch *gFdbOrch;
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
extern sai_neighbor_api_t *sai_neighbor_api;
extern sai_router_interface_api_t *sai_router_intfs_api;
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
                    /* Comma-separated list of peer T1 VTEP IPs for HW FRR.
                     * Order defines bitmask indexing: peer[0]=bit 0, etc. */
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
                else if (fvField(i) == "l3_vni")
                {
                    uint32_t vni = 0;
                    try { vni = static_cast<uint32_t>(stoul(fvValue(i))); }
                    catch (...) { vni = 0; }
                    if (vni != 0)
                    {
                        m_esL3Vni[key] = vni;
                        SWSS_LOG_NOTICE("EVPN MH: l3_vni for %s set to %u",
                            key.c_str(), vni);
                    }
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

            /* HW/L3 FRR: create protection groups if configured */
            auto mode_it = m_esFailoverMode.find(key);
            if (mode_it != m_esFailoverMode.end() &&
                (mode_it->second == EvpnMhFailoverMode::HW ||
                 mode_it->second == EvpnMhFailoverMode::L3))
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
    /* Check static server IPs from ConfigDB */
    for (auto const &es_entry : m_esServerIps)
    {
        const std::string &port_name = es_entry.first;
        auto mode = getEffectiveFailoverMode(port_name);
        if (mode != EvpnMhFailoverMode::HW && mode != EvpnMhFailoverMode::L3)
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

    /* Check dynamically added routes in protection groups (HW mode only —
     * L3 mode needs adjacency-sourced /32 for VPP NH resolution) */
    for (auto const &state_entry : m_hwFrrState)
    {
        auto mode = getEffectiveFailoverMode(state_entry.first);
        if (mode != EvpnMhFailoverMode::HW)
            continue;
        for (auto const &route : state_entry.second.server_routes)
        {
            if (route.server_ip.getIp() == ip)
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
 *   active_vteps: comma-separated list of currently active peer VTEP IPs
 *
 * This is triggered when fdbsyncd detects ES remote VTEP changes via FRR
 * (BGP EVPN Type-4 ES route add/withdraw from peers).
 *
 * Calls updateHwFrrStandbyEcmp() to reprogram the standby ECMP NHG members.
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

            SWSS_LOG_NOTICE("EVPN MH ES state: %s active_vteps=%zu",
                            es_port.c_str(), active_vtep_set.size());

            sai_status_t status = updateHwFrrStandbyEcmp(es_port, active_vtep_set);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("EVPN MH ES state: failed to update standby ECMP for %s (status=%d)",
                               es_port.c_str(), status);
                ++it;
                continue;
            }
        }
        else if (op == DEL_COMMAND)
        {
            /* ES gone — all peers down, clear standby ECMP */
            auto state_it = m_hwFrrState.find(es_port);
            if (state_it != m_hwFrrState.end())
            {
                SWSS_LOG_NOTICE("EVPN MH ES state: %s removed — clearing standby ECMP",
                                es_port.c_str());
                std::set<std::string> empty;
                updateHwFrrStandbyEcmp(es_port, empty);
            }
        }

        it = consumer.m_toSync.erase(it);
    }
}

/*
 * Query FRR for the list of active remote VTEPs on a given ES port.
 * Returns a set of VTEP IP strings from `show evpn es detail`.
 * Used by HW FRR to determine the active peer mask.
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
 * Check if LACP is in "current" state for a PortChannel.
 * Reads STATE_DB LAG_MEMBER_TABLE entries for any member of the LAG.
 * Returns true if at least one member has runner.state=current and runner.selected=true.
 * Returns true (default to local path) on any error.
 */
bool EvpnMhOrch::isLacpCurrent(const std::string &port_channel)
{
    try
    {
        swss::DBConnector stateDb("STATE_DB", 0);
        /* Find member keys matching LAG_MEMBER_TABLE|<port_channel>|* */
        std::string pattern = "LAG_MEMBER_TABLE|" + port_channel + "|*";
        auto keys = stateDb.keys(pattern);

        for (const auto &key : keys)
        {
            auto state = stateDb.hget(key, "runner.state");
            auto selected = stateDb.hget(key, "runner.selected");
            if (state && *state == "current" && selected && *selected == "true")
            {
                SWSS_LOG_NOTICE("isLacpCurrent: %s member %s is current+selected",
                    port_channel.c_str(), key.c_str());
                return true;
            }
        }

        if (keys.empty())
        {
            SWSS_LOG_NOTICE("isLacpCurrent: no LAG_MEMBER_TABLE entries for %s, defaulting to true",
                port_channel.c_str());
            return true;
        }

        SWSS_LOG_NOTICE("isLacpCurrent: %s has %zu members but none current+selected",
            port_channel.c_str(), keys.size());
        return false;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("isLacpCurrent: exception for %s: %s, defaulting to true",
            port_channel.c_str(), e.what());
        return true;
    }
}

/*
 * HW FRR Protection Groups — Per-ES provisioning
 *
 * Each ES port gets ONE PROTECTION NHG:
 *   - PRIMARY member: local NH (via bvi/VLAN RIF) with MONITORED_OBJECT = PortChannel
 *   - STANDBY member: ECMP NHG across all peer VTEP tunnel NHs
 *
 * All server /32 routes on this ES point to the same PROTECTION NHG.
 *
 * On link failure:
 *   1. ASIC instantly switches to standby ECMP NHG (MONITORED_OBJECT)
 *   2. BGP EVPN Type-4 update → reprogram standby ECMP NHG members
 *
 * Tunnel NHs are shared across ES ports via m_l3TunnelNexthops.
 */
sai_status_t EvpnMhOrch::createHwFrrProtectionGroups(const std::string &es_port)
{
    SWSS_LOG_ENTER();

    /* Gather peer VTEPs: prefer peer_vteps list, fall back to single peer_vtep */
    std::vector<std::string> peer_ips;
    auto vtep_list_it = m_esPeerVtepList.find(es_port);
    if (vtep_list_it != m_esPeerVtepList.end() && !vtep_list_it->second.empty())
    {
        peer_ips = vtep_list_it->second;
    }
    else
    {
        auto vtep_it = m_esPeerVtep.find(es_port);
        if (vtep_it != m_esPeerVtep.end() && !vtep_it->second.empty())
        {
            peer_ips.push_back(vtep_it->second);
        }
    }

    if (peer_ips.empty())
    {
        SWSS_LOG_ERROR("HW FRR: no peer VTEPs for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    auto server_ips = getServerIpsForEsPort(es_port);
    /* server_ips may be empty for L3 mode — /32 routes are added dynamically
     * as neighbors appear via EVPN Type-2. Protection NHG infrastructure is
     * still created; routes are installed later via addHwFrrServerRoute(). */

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
        pc_oid = es_port_obj.m_port_id;
    }

    SWSS_LOG_NOTICE("HW FRR: creating protection group for ES port %s: "
                    "%zu peers, %zu server IPs, VRF 0x%" PRIx64 ", RIF 0x%" PRIx64,
                    es_port.c_str(), peer_ips.size(),
                    server_ips.size(), vrf_oid, vlan_rif_oid);

    /* Initialize per-ES state */
    EsHwFrrState &state = m_hwFrrState[es_port];
    state.es_port = es_port;
    state.peers.clear();
    state.server_routes.clear();

    /* ---- Step 0: Ensure VRF→VNI encap mapper entry exists ---- */
    /* Without this entry, the VPP SAI tunnel_encap_nexthop_action() cannot
     * determine which VNI to use for VxLAN encap, and silently skips VPP
     * tunnel creation — leaving the PROTECTION NHG standby path dead. */
    {
        EvpnNvoOrch* evpn_nvo_orch = gDirectory.get<EvpnNvoOrch*>();
        VxlanTunnel* sip_tunnel = evpn_nvo_orch->getEVPNVtep();
        if (sip_tunnel)
        {
            uint32_t l3vni = 0;
            auto vni_it = m_esL3Vni.find(es_port);
            if (vni_it != m_esL3Vni.end())
            {
                l3vni = vni_it->second;
            }
            if (l3vni != 0)
            {
                auto mapper_pair = sip_tunnel->getMapperEntry(l3vni);
                if (mapper_pair.first == SAI_NULL_OBJECT_ID)
                {
                    /* Create VRF→VNI encap mapper entry */
                    sai_object_id_t encap_entry = sip_tunnel->addEncapMapperEntry(
                        vrf_oid, l3vni, TUNNEL_MAP_T_VIRTUAL_ROUTER);
                    if (encap_entry != SAI_NULL_OBJECT_ID)
                    {
                        /* Also store in tunnel's mapper cache so it's not created twice */
                        sip_tunnel->insertMapperEntry(encap_entry, mapper_pair.second, l3vni);
                        SWSS_LOG_NOTICE("HW FRR: created VRF→VNI encap mapper entry: "
                                        "VRF 0x%" PRIx64 " → VNI %u (entry 0x%" PRIx64 ")",
                                        vrf_oid, l3vni, encap_entry);
                    }
                    else
                    {
                        SWSS_LOG_ERROR("HW FRR: failed to create VRF→VNI encap mapper entry "
                                       "for VRF 0x%" PRIx64 " VNI %u", vrf_oid, l3vni);
                    }
                }
                else
                {
                    SWSS_LOG_NOTICE("HW FRR: VRF→VNI encap mapper entry already exists "
                                    "for VNI %u (entry 0x%" PRIx64 ")", l3vni, mapper_pair.first);
                }
            }
            else
            {
                SWSS_LOG_WARN("HW FRR: no L3 VNI configured for ES port %s, "
                              "tunnel encap may not work", es_port.c_str());
            }
        }
    }

    /* ---- Step 1: Create tunnel NHs for each peer VTEP ---- */
    for (size_t i = 0; i < peer_ips.size(); i++)
    {
        sai_object_id_t nh_oid = getL3TunnelNexthop(peer_ips[i]);
        if (nh_oid == SAI_NULL_OBJECT_ID)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create tunnel NH for peer %s",
                           peer_ips[i].c_str());
            removeHwFrrProtectionGroups(es_port);
            return SAI_STATUS_FAILURE;
        }

        PeerVtep peer;
        peer.vtep_ip = peer_ips[i];
        peer.nh_tunnel_oid = nh_oid;
        peer.ecmp_member_oid = SAI_NULL_OBJECT_ID;  // Set when ECMP NHG is created
        state.peers.push_back(peer);

        SWSS_LOG_NOTICE("HW FRR: peer[%zu] = %s → NH 0x%" PRIx64,
                        i, peer_ips[i].c_str(), nh_oid);
    }

    /* ---- Step 2: Create standby ECMP NHG with all peer tunnel NHs ---- */
    {
        sai_attribute_t nhg_attr;
        nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
        nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_ECMP;

        sai_status_t status = sai_next_hop_group_api->create_next_hop_group(
            &state.standby_ecmp_nhg_oid, gSwitchId, 1, &nhg_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create standby ECMP NHG (status=%d)", status);
            removeHwFrrProtectionGroups(es_port);
            return status;
        }

        SWSS_LOG_NOTICE("HW FRR: standby ECMP NHG = 0x%" PRIx64,
                        state.standby_ecmp_nhg_oid);

        /* Add each peer as an ECMP member */
        for (auto &peer : state.peers)
        {
            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = state.standby_ecmp_nhg_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = peer.nh_tunnel_oid;
            mbr_attrs.push_back(attr);

            status = sai_next_hop_group_api->create_next_hop_group_member(
                &peer.ecmp_member_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()),
                mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to add peer %s to ECMP NHG (status=%d)",
                               peer.vtep_ip.c_str(), status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }

            SWSS_LOG_NOTICE("HW FRR: ECMP member for %s = 0x%" PRIx64,
                            peer.vtep_ip.c_str(), peer.ecmp_member_oid);
        }
    }

    /* ---- Step 3: Create local NH for primary path ---- */
    {
        /* For the primary local NH, we need any IP that resolves via the VLAN
         * RIF.  If server IPs are configured, use the first one.  Otherwise
         * use the VLAN SVI's own IP (always available). */
        std::string ip_str;
        if (!server_ips.empty())
        {
            ip_str = server_ips[0].getIp().to_string();
        }
        else
        {
            /* No static server IPs configured — defer PROTECTION NHG creation
             * until the first server route is dynamically added via
             * addHwFrrServerRoute() from neighorch.  Using the SVI's own IP
             * (e.g. 10.0.0.1) would create a NH that resolves to self, causing
             * arp-ipv4 glean instead of forwarding to the server. */
            SWSS_LOG_NOTICE("HW FRR: no server IPs for %s, "
                            "deferring PROTECTION NHG until first neighbor learn",
                            es_port.c_str());
            state.prot_nhg_oid = SAI_NULL_OBJECT_ID;
            return SAI_STATUS_SUCCESS;
        }
        IpAddress server_addr(ip_str);
        NextHopKey nh_key(server_addr, vlan_alias);

        if (gNeighOrch->hasNextHop(nh_key))
        {
            state.nh_local_oid = gNeighOrch->getNextHopId(nh_key);
            state.owns_local_nh = false;
            SWSS_LOG_NOTICE("HW FRR: borrowed local NH for %s → 0x%" PRIx64,
                            ip_str.c_str(), state.nh_local_oid);
        }
        else
        {
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
                &state.nh_local_oid, gSwitchId,
                static_cast<uint32_t>(nh_attrs.size()),
                nh_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to create local NH for %s (status=%d)",
                               ip_str.c_str(), status);
                removeHwFrrProtectionGroups(es_port);
                return status;
            }
            state.owns_local_nh = true;
            SWSS_LOG_NOTICE("HW FRR: created local NH for %s → 0x%" PRIx64,
                            ip_str.c_str(), state.nh_local_oid);
        }
    }

    /* ---- Step 4: Create the single PROTECTION NHG for this ES ---- */
    {
        sai_attribute_t nhg_attr;
        nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
        nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_PROTECTION;

        sai_status_t status = sai_next_hop_group_api->create_next_hop_group(
            &state.prot_nhg_oid, gSwitchId, 1, &nhg_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create PROTECTION NHG (status=%d)", status);
            removeHwFrrProtectionGroups(es_port);
            return status;
        }

        SWSS_LOG_NOTICE("HW FRR: PROTECTION NHG = 0x%" PRIx64, state.prot_nhg_oid);
    }

    /* ---- Step 4a: Create PRIMARY member (local NH, MONITORED_OBJECT = PC) ---- */
    {
        std::vector<sai_attribute_t> mbr_attrs;
        sai_attribute_t attr;

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
        attr.value.oid = state.prot_nhg_oid;
        mbr_attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        attr.value.oid = state.nh_local_oid;
        mbr_attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE;
        attr.value.s32 = SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_PRIMARY;
        mbr_attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_MONITORED_OBJECT;
        attr.value.oid = pc_oid;
        mbr_attrs.push_back(attr);

        sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
            &state.primary_member_oid, gSwitchId,
            static_cast<uint32_t>(mbr_attrs.size()),
            mbr_attrs.data());
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create PRIMARY member (status=%d)", status);
            removeHwFrrProtectionGroups(es_port);
            return status;
        }
    }

    /* ---- Step 4b: Create STANDBY member → standby ECMP NHG ---- */
    {
        std::vector<sai_attribute_t> mbr_attrs;
        sai_attribute_t attr;

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
        attr.value.oid = state.prot_nhg_oid;
        mbr_attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        attr.value.oid = state.standby_ecmp_nhg_oid;
        mbr_attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE;
        attr.value.s32 = SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_STANDBY;
        mbr_attrs.push_back(attr);

        sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
            &state.standby_member_oid, gSwitchId,
            static_cast<uint32_t>(mbr_attrs.size()),
            mbr_attrs.data());
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create STANDBY member (status=%d)", status);
            removeHwFrrProtectionGroups(es_port);
            return status;
        }
    }

    SWSS_LOG_NOTICE("HW FRR: PROTECTION NHG 0x%" PRIx64 ": PRIMARY=0x%" PRIx64
                    " (local_nh=0x%" PRIx64 " monitored=%s) STANDBY=0x%" PRIx64
                    " (ecmp_nhg=0x%" PRIx64 " with %zu peers)",
                    state.prot_nhg_oid, state.primary_member_oid,
                    state.nh_local_oid, es_port.c_str(),
                    state.standby_member_oid, state.standby_ecmp_nhg_oid,
                    state.peers.size());

    /* ---- Step 5: Create /32 routes for all server IPs ---- */
    /* If LACP is current (local server), route → PROTECTION NHG (primary=local, standby=tunnel).
     * If LACP is defaulted (remote server), route → direct tunnel NH (no local path). */
    bool lacp_current = isLacpCurrent(es_port);

    for (const auto &server_ip : server_ips)
    {
        HwFrrServerRoute route;
        route.server_ip = server_ip;
        route.nh_local_oid = SAI_NULL_OBJECT_ID;  // Not per-server anymore
        route.owns_local_nh = false;
        route.owns_route = false;
        route.uses_protection = lacp_current;

        sai_route_entry_t route_entry;
        route_entry.switch_id = gSwitchId;
        route_entry.vr_id = vrf_oid;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        std::string ip_str = server_ip.getIp().to_string();
        inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);

        std::string mask_str = server_ip.getMask().to_string();
        inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

        sai_attribute_t route_attr;
        route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;

        if (lacp_current)
        {
            route_attr.value.oid = state.prot_nhg_oid;
            SWSS_LOG_NOTICE("HW FRR: LACP current on %s — route %s → PROTECTION NHG 0x%" PRIx64,
                            es_port.c_str(), server_ip.to_string().c_str(), state.prot_nhg_oid);
        }
        else
        {
            /* LACP defaulted — server is remote, route directly via tunnel */
            route_attr.value.oid = state.peers[0].nh_tunnel_oid;
            SWSS_LOG_NOTICE("HW FRR: LACP defaulted on %s — route %s → tunnel NH 0x%" PRIx64,
                            es_port.c_str(), server_ip.to_string().c_str(),
                            state.peers[0].nh_tunnel_oid);
        }

        sai_status_t status = sai_route_api->create_route_entry(
            &route_entry, 1, &route_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR: failed to create route %s → PROTECTION NHG (status=%d)",
                           server_ip.to_string().c_str(), status);
            removeHwFrrProtectionGroups(es_port);
            return status;
        }

        route.owns_route = true;
        state.server_routes.push_back(route);

        SWSS_LOG_NOTICE("HW FRR: route %s → %s 0x%" PRIx64,
                        server_ip.to_string().c_str(),
                        lacp_current ? "PROTECTION NHG" : "tunnel NH",
                        route_attr.value.oid);

        /* ---- ARP termination entry for this server IP ----
         *
         * Create a SAI neighbor on the overlay VLAN RIF (e.g. Vlan10) with
         * the anycast gateway MAC.  This triggers:
         *   (1) VPP BD arp-term entry — VPP responds to ARP for this IP
         *   (2) Static VPP neighbor with real MAC (for L3 hairpin)
         *   (3) Kernel neighbor on bvivlan<N> and Vlan<N> (for FRR Type-2)
         *
         * Without this, remote server IPs are unreachable: ARP from local
         * servers into the BD gets intercepted by arp-term which has no
         * entry → ARP fails → "Destination Host Unreachable".
         *
         * The NO_HOST_ROUTE flag is set to suppress the /32 FIB entry
         * (our PROTECTION NHG route owns the /32 exclusively).
         *
         * Note: the real server MAC is unknown at this point — we use
         * the anycast GW MAC.  The SAI code detects same_mac and programs
         * only the arp-term entry (no L3 hairpin neighbor).  The real MAC
         * will be learned dynamically via clone-to-BVI when the server
         * actually sends ARP.
         */
        if (vlan_rif_oid != SAI_NULL_OBJECT_ID)
        {
            sai_neighbor_entry_t nbr_entry;
            nbr_entry.switch_id = gSwitchId;
            nbr_entry.rif_id = vlan_rif_oid;
            nbr_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            inet_pton(AF_INET, ip_str.c_str(), &nbr_entry.ip_address.addr.ip4);

            /* Get the anycast GW MAC from the overlay VLAN RIF */
            sai_attribute_t rif_attr;
            rif_attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
            sai_mac_t gw_mac = {};
            bool have_gw_mac = false;
            if (sai_router_intfs_api->get_router_interface_attribute(
                    vlan_rif_oid, 1, &rif_attr) == SAI_STATUS_SUCCESS)
            {
                memcpy(gw_mac, rif_attr.value.mac, sizeof(sai_mac_t));
                /* Verify not all zeros */
                for (int m = 0; m < 6; m++) {
                    if (gw_mac[m] != 0) { have_gw_mac = true; break; }
                }
            }

            if (have_gw_mac)
            {
                std::vector<sai_attribute_t> nbr_attrs;
                sai_attribute_t nattr;
                nattr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
                memcpy(nattr.value.mac, gw_mac, sizeof(sai_mac_t));
                nbr_attrs.push_back(nattr);
                nattr.id = SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE;
                nattr.value.booldata = true;
                nbr_attrs.push_back(nattr);

                sai_status_t nbr_status = sai_neighbor_api->create_neighbor_entry(
                    &nbr_entry,
                    static_cast<uint32_t>(nbr_attrs.size()),
                    nbr_attrs.data());

                if (nbr_status == SAI_STATUS_SUCCESS ||
                    nbr_status == SAI_STATUS_ITEM_ALREADY_EXISTS)
                {
                    SWSS_LOG_NOTICE("HW FRR: created ARP-term neighbor for %s on "
                                    "overlay VLAN RIF 0x%" PRIx64,
                                    ip_str.c_str(), vlan_rif_oid);
                }
                else
                {
                    SWSS_LOG_WARN("HW FRR: failed to create ARP-term neighbor for %s "
                                  "(status=%d)", ip_str.c_str(), nbr_status);
                }
            }
        }
    }

    SWSS_LOG_NOTICE("HW FRR: ES port %s fully provisioned: %zu peers, "
                    "1 PROTECTION NHG, 1 standby ECMP NHG, %zu server routes",
                    es_port.c_str(), state.peers.size(), state.server_routes.size());
    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Remove all protection group objects for an ES port.
 * Order: routes → PROTECTION NHG members → PROTECTION NHG →
 *        ECMP NHG members → ECMP NHG → local NH (if owned).
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
    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);

    /* Remove server /32 routes */
    for (auto &route : state.server_routes)
    {
        if (route.owns_route && vrf_oid != SAI_NULL_OBJECT_ID)
        {
            sai_route_entry_t route_entry;
            route_entry.switch_id = gSwitchId;
            route_entry.vr_id = vrf_oid;
            route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

            std::string ip_str = route.server_ip.getIp().to_string();
            inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
            std::string mask_str = route.server_ip.getMask().to_string();
            inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

            sai_route_api->remove_route_entry(&route_entry);
        }
    }

    /* Remove PROTECTION NHG members, then NHG */
    if (state.standby_member_oid != SAI_NULL_OBJECT_ID)
        sai_next_hop_group_api->remove_next_hop_group_member(state.standby_member_oid);
    if (state.primary_member_oid != SAI_NULL_OBJECT_ID)
        sai_next_hop_group_api->remove_next_hop_group_member(state.primary_member_oid);
    if (state.prot_nhg_oid != SAI_NULL_OBJECT_ID)
        sai_next_hop_group_api->remove_next_hop_group(state.prot_nhg_oid);

    /* Remove ECMP NHG members, then NHG */
    for (auto &peer : state.peers)
    {
        if (peer.ecmp_member_oid != SAI_NULL_OBJECT_ID)
            sai_next_hop_group_api->remove_next_hop_group_member(peer.ecmp_member_oid);
    }
    if (state.standby_ecmp_nhg_oid != SAI_NULL_OBJECT_ID)
        sai_next_hop_group_api->remove_next_hop_group(state.standby_ecmp_nhg_oid);

    /* Remove local NH only if we created it */
    if (state.owns_local_nh && state.nh_local_oid != SAI_NULL_OBJECT_ID)
        sai_next_hop_api->remove_next_hop(state.nh_local_oid);

    SWSS_LOG_NOTICE("HW FRR: removed all objects for ES port %s (%zu routes)",
                    es_port.c_str(), state.server_routes.size());

    m_hwFrrState.erase(state_it);
    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Update the standby ECMP NHG members when the set of active
 * peer VTEPs changes (triggered by EVPN Type-4 ES route updates).
 *
 * This is O(N) where N = number of peer VTEPs (typically 1-7).
 * It adds/removes ECMP NHG members to match the new active set.
 * All server routes continue pointing to the same PROTECTION NHG — no
 * per-server updates needed.
 */
sai_status_t EvpnMhOrch::updateHwFrrStandbyEcmp(
    const std::string &es_port,
    const std::set<std::string> &active_vteps)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        SWSS_LOG_WARN("HW FRR: no state for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    EsHwFrrState &state = state_it->second;

    SWSS_LOG_NOTICE("HW FRR: updating standby ECMP for %s: %zu active VTEPs",
                    es_port.c_str(), active_vteps.size());

    if (active_vteps.empty())
    {
        SWSS_LOG_WARN("HW FRR: ALL peers down for ES port %s — no backup path!",
                      es_port.c_str());
        /* Remove all ECMP members but keep the NHG (so PROTECTION NHG stays valid) */
        for (auto &peer : state.peers)
        {
            if (peer.ecmp_member_oid != SAI_NULL_OBJECT_ID)
            {
                sai_next_hop_group_api->remove_next_hop_group_member(peer.ecmp_member_oid);
                peer.ecmp_member_oid = SAI_NULL_OBJECT_ID;
            }
        }
        return SAI_STATUS_SUCCESS;
    }

    /* For each peer: add member if newly active, remove if no longer active */
    for (auto &peer : state.peers)
    {
        bool should_be_active = (active_vteps.count(peer.vtep_ip) > 0);
        bool is_active = (peer.ecmp_member_oid != SAI_NULL_OBJECT_ID);

        if (should_be_active && !is_active)
        {
            /* Add member */
            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = state.standby_ecmp_nhg_oid;
            mbr_attrs.push_back(attr);

            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = peer.nh_tunnel_oid;
            mbr_attrs.push_back(attr);

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
                &peer.ecmp_member_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()),
                mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to add peer %s to ECMP NHG (status=%d)",
                               peer.vtep_ip.c_str(), status);
                return status;
            }

            SWSS_LOG_NOTICE("HW FRR: added peer %s to standby ECMP (member=0x%" PRIx64 ")",
                            peer.vtep_ip.c_str(), peer.ecmp_member_oid);
        }
        else if (!should_be_active && is_active)
        {
            /* Remove member */
            sai_status_t status = sai_next_hop_group_api->remove_next_hop_group_member(
                peer.ecmp_member_oid);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("HW FRR: failed to remove peer %s from ECMP NHG (status=%d)",
                               peer.vtep_ip.c_str(), status);
                return status;
            }

            SWSS_LOG_NOTICE("HW FRR: removed peer %s from standby ECMP",
                            peer.vtep_ip.c_str());
            peer.ecmp_member_oid = SAI_NULL_OBJECT_ID;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Handle local port down event.
 * VPP doesn't natively implement MONITORED_OBJECT for PROTECTION NHGs,
 * so we do it in software: swap each server IP route from the PROTECTION NHG
 * to the standby ECMP NHG directly.
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

    for (auto &route : state.server_routes)
    {
        sai_route_entry_t route_entry;
        route_entry.switch_id = gSwitchId;
        route_entry.vr_id = vrf_oid;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        std::string ip_str = route.server_ip.getIp().to_string();
        std::string mask_str = route.server_ip.getMask().to_string();
        inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
        inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

        sai_attribute_t route_attr;
        route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        route_attr.value.oid = state.standby_ecmp_nhg_oid;

        sai_status_t status = sai_route_api->set_route_entry_attribute(
            &route_entry, &route_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR port down: failed to swap route %s (status=%d)",
                           route.server_ip.to_string().c_str(), status);
            continue;
        }

        SWSS_LOG_NOTICE("HW FRR port down: %s route %s → standby ECMP NHG (0x%" PRIx64 ")",
                        es_port.c_str(), route.server_ip.to_string().c_str(),
                        state.standby_ecmp_nhg_oid);
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * HW FRR — Handle local port up event.
 * Restore each server IP route to the PROTECTION NHG (which includes
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

    for (auto &route : state.server_routes)
    {
        sai_route_entry_t route_entry;
        route_entry.switch_id = gSwitchId;
        route_entry.vr_id = vrf_oid;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        std::string ip_str = route.server_ip.getIp().to_string();
        std::string mask_str = route.server_ip.getMask().to_string();
        inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
        inet_pton(AF_INET, mask_str.c_str(), &route_entry.destination.mask.ip4);

        sai_attribute_t route_attr;
        route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        route_attr.value.oid = state.prot_nhg_oid;

        sai_status_t status = sai_route_api->set_route_entry_attribute(
            &route_entry, &route_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("HW FRR port up: failed to restore route %s (status=%d)",
                           route.server_ip.to_string().c_str(), status);
            continue;
        }

        SWSS_LOG_NOTICE("HW FRR port up: %s route %s → PROTECTION NHG (0x%" PRIx64 ")",
                        es_port.c_str(), route.server_ip.to_string().c_str(),
                        state.prot_nhg_oid);
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Find the ES port associated with a VLAN neighbor.  Checks all ES ports'
 * VLAN membership to find which ES port is on this VLAN.
 */
std::string EvpnMhOrch::getEsPortForVlanNeighbor(const std::string &vlan_alias, const IpAddress &ip,
                                                  const MacAddress &mac)
{
    /* First, try to find the ES port via the FDB: look up which PortChannel
     * the neighbor's MAC is learned on. This is the correct mapping when
     * multiple ES ports share the same VLAN (e.g. two PortChannels in Vlan10). */
    if (gFdbOrch && mac)
    {
        Port vlan_port;
        if (gPortsOrch->getPort(vlan_alias, vlan_port))
        {
            FdbEntry fdb_entry;
            fdb_entry.mac = mac;
            fdb_entry.bv_id = vlan_port.m_vlan_info.vlan_oid;
            FdbData fdb_data;
            if (gFdbOrch->getFdbEntry(fdb_entry, fdb_data))
            {
                /* Find which ES port owns this bridge_port_id */
                for (const auto &es_entry : m_esIntfMap)
                {
                    Port es_port_obj;
                    if (!gPortsOrch->getPort(es_entry.first, es_port_obj))
                        continue;
                    if (es_port_obj.m_bridge_port_id == fdb_data.bridge_port_id)
                    {
                        SWSS_LOG_NOTICE("getEsPortForVlanNeighbor: IP %s MAC %s → %s (via FDB)",
                                        ip.to_string().c_str(), mac.to_string().c_str(),
                                        es_entry.first.c_str());
                        return es_entry.first;
                    }
                }
            }
        }
    }

    /* Fallback: return the ES port only when there's exactly ONE ES port in
     * the VLAN.  With multiple ES ports, the fallback would pick the first
     * iterator entry which is essentially random — causing the NHG sharing
     * bug where both server routes land on the same PROTECTION NHG.
     *
     * When ambiguous (multiple ES ports, FDB not yet learned locally),
     * return empty string so the caller can defer until FDB resolves. */
    std::string single_match;
    int match_count = 0;
    for (const auto &es_entry : m_esIntfMap)
    {
        const std::string &port_name = es_entry.first;

        Port es_port_obj;
        if (!gPortsOrch->getPort(port_name, es_port_obj))
            continue;

        vlan_members_t vlan_members;
        gPortsOrch->getPortVlanMembers(es_port_obj, vlan_members);
        for (const auto &member : vlan_members)
        {
            std::string member_vlan = std::string(VLAN_PREFIX) + std::to_string(member.first);
            if (member_vlan == vlan_alias)
            {
                match_count++;
                single_match = port_name;
                break;
            }
        }
    }

    if (match_count == 1)
    {
        SWSS_LOG_NOTICE("getEsPortForVlanNeighbor: IP %s → %s (fallback, single ES port in VLAN)",
                        ip.to_string().c_str(), single_match.c_str());
        return single_match;
    }

    if (match_count > 1)
    {
        SWSS_LOG_NOTICE("getEsPortForVlanNeighbor: IP %s MAC %s → deferred (%d ES ports in %s, "
                        "FDB not on local ES port yet)",
                        ip.to_string().c_str(), mac.to_string().c_str(),
                        match_count, vlan_alias.c_str());
    }
    return "";
}

void EvpnMhOrch::deferHwFrrRoute(const std::string &vlan_alias, const IpAddress &ip,
                                  const MacAddress &mac)
{
    /* Only stash if we actually have HW FRR state (i.e. ES ports configured) */
    if (m_hwFrrState.empty())
        return;

    /* Avoid duplicates */
    for (const auto &p : m_pendingHwFrrRoutes)
    {
        if (p.server_ip == ip)
            return;
    }

    SWSS_LOG_NOTICE("deferHwFrrRoute: stashing %s (MAC %s, VLAN %s) for retry on local FDB learn",
                    ip.to_string().c_str(), mac.to_string().c_str(), vlan_alias.c_str());
    m_pendingHwFrrRoutes.push_back({vlan_alias, ip, mac});
}

void EvpnMhOrch::retryPendingHwFrrRoutes(const std::string &es_port, const MacAddress &mac)
{
    if (m_pendingHwFrrRoutes.empty())
        return;

    /* Iterate pending routes and resolve any whose MAC matches */
    auto it = m_pendingHwFrrRoutes.begin();
    while (it != m_pendingHwFrrRoutes.end())
    {
        if (it->mac == mac)
        {
            SWSS_LOG_NOTICE("retryPendingHwFrrRoutes: resolving deferred route %s "
                            "(MAC %s) → ES port %s",
                            it->server_ip.to_string().c_str(),
                            mac.to_string().c_str(), es_port.c_str());

            auto mode = getEffectiveFailoverMode(es_port);
            if (mode == EvpnMhFailoverMode::HW || mode == EvpnMhFailoverMode::L3)
            {
                addHwFrrServerRoute(es_port, it->server_ip);
            }
            it = m_pendingHwFrrRoutes.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

/*
 * Dynamically add a /32 server route to an existing protection group.
 * Called by neighorch when a new neighbor is learned on a VLAN interface
 * associated with an ES port (L3/HW FRR mode).
 */
sai_status_t EvpnMhOrch::addHwFrrServerRoute(const std::string &es_port, const IpAddress &server_ip)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        SWSS_LOG_NOTICE("addHwFrrServerRoute: no protection group for %s, skipping",
                        es_port.c_str());
        return SAI_STATUS_SUCCESS;
    }

    EsHwFrrState &state = state_it->second;

    /* If PROTECTION NHG was deferred (no server IPs at creation time),
     * now we have a real server IP — complete the protection group. */
    if (state.prot_nhg_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_NOTICE("addHwFrrServerRoute: completing deferred PROTECTION NHG for %s "
                        "using server IP %s", es_port.c_str(), server_ip.to_string().c_str());

        /* Find VLAN alias and RIF for this ES port */
        Port es_port_obj;
        if (!gPortsOrch->getPort(es_port, es_port_obj))
        {
            SWSS_LOG_ERROR("addHwFrrServerRoute: port %s not found", es_port.c_str());
            return SAI_STATUS_FAILURE;
        }

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
            SWSS_LOG_ERROR("addHwFrrServerRoute: no VLAN RIF for ES port %s", es_port.c_str());
            return SAI_STATUS_FAILURE;
        }

        sai_object_id_t pc_oid = es_port_obj.m_lag_id;
        if (pc_oid == SAI_NULL_OBJECT_ID)
            pc_oid = es_port_obj.m_port_id;

        /* Create local NH using this server IP */
        NextHopKey nh_key(server_ip, vlan_alias);
        if (gNeighOrch->hasNextHop(nh_key))
        {
            state.nh_local_oid = gNeighOrch->getNextHopId(nh_key);
            state.owns_local_nh = false;
        }
        else
        {
            sai_ip_address_t sai_ip;
            sai_ip.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            inet_pton(AF_INET, server_ip.to_string().c_str(), &sai_ip.addr.ip4);

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
                &state.nh_local_oid, gSwitchId,
                static_cast<uint32_t>(nh_attrs.size()), nh_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("addHwFrrServerRoute: failed to create local NH (status=%d)", status);
                return status;
            }
            state.owns_local_nh = true;
        }

        /* Create PROTECTION NHG */
        {
            sai_attribute_t nhg_attr;
            nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
            nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_PROTECTION;

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group(
                &state.prot_nhg_oid, gSwitchId, 1, &nhg_attr);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("addHwFrrServerRoute: failed to create PROTECTION NHG (status=%d)", status);
                return status;
            }
        }

        /* PRIMARY member (local NH, MONITORED_OBJECT = PC) */
        {
            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = state.prot_nhg_oid;
            mbr_attrs.push_back(attr);
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = state.nh_local_oid;
            mbr_attrs.push_back(attr);
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE;
            attr.value.s32 = SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_PRIMARY;
            mbr_attrs.push_back(attr);
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_MONITORED_OBJECT;
            attr.value.oid = pc_oid;
            mbr_attrs.push_back(attr);

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
                &state.primary_member_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()), mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("addHwFrrServerRoute: failed to create PRIMARY member (status=%d)", status);
                return status;
            }
        }

        /* STANDBY member → standby ECMP NHG */
        {
            std::vector<sai_attribute_t> mbr_attrs;
            sai_attribute_t attr;
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
            attr.value.oid = state.prot_nhg_oid;
            mbr_attrs.push_back(attr);
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            attr.value.oid = state.standby_ecmp_nhg_oid;
            mbr_attrs.push_back(attr);
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE;
            attr.value.s32 = SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_STANDBY;
            mbr_attrs.push_back(attr);

            sai_status_t status = sai_next_hop_group_api->create_next_hop_group_member(
                &state.standby_member_oid, gSwitchId,
                static_cast<uint32_t>(mbr_attrs.size()), mbr_attrs.data());
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("addHwFrrServerRoute: failed to create STANDBY member (status=%d)", status);
                return status;
            }
        }

        SWSS_LOG_NOTICE("addHwFrrServerRoute: deferred PROTECTION NHG 0x%" PRIx64
                        " completed for ES %s", state.prot_nhg_oid, es_port.c_str());
    }

    /* Check if route already exists */
    for (const auto &route : state.server_routes)
    {
        if (route.server_ip.getIp() == server_ip)
        {
            SWSS_LOG_NOTICE("addHwFrrServerRoute: %s already has route for %s",
                            es_port.c_str(), server_ip.to_string().c_str());
            return SAI_STATUS_SUCCESS;
        }
    }

    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);
    if (vrf_oid == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_ERROR("addHwFrrServerRoute: no VRF for ES port %s", es_port.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Create /32 route → PROTECTION NHG */
    IpPrefix server_prefix(server_ip.to_string() + "/32");

    HwFrrServerRoute route;
    route.server_ip = server_prefix;
    route.nh_local_oid = SAI_NULL_OBJECT_ID;
    route.owns_local_nh = false;
    route.owns_route = false;

    sai_route_entry_t route_entry;
    route_entry.switch_id = gSwitchId;
    route_entry.vr_id = vrf_oid;
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

    std::string ip_str = server_ip.to_string();
    inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
    inet_pton(AF_INET, "255.255.255.255", &route_entry.destination.mask.ip4);

    sai_attribute_t route_attr;
    route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    route_attr.value.oid = state.prot_nhg_oid;

    sai_status_t status = sai_route_api->create_route_entry(
        &route_entry, 1, &route_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("addHwFrrServerRoute: failed to create route %s → PROTECTION NHG for %s (status=%d)",
                       ip_str.c_str(), es_port.c_str(), status);
        return status;
    }

    route.owns_route = true;
    state.server_routes.push_back(route);

    SWSS_LOG_NOTICE("addHwFrrServerRoute: %s → PROTECTION NHG 0x%" PRIx64 " for ES %s",
                    ip_str.c_str(), state.prot_nhg_oid, es_port.c_str());
    return SAI_STATUS_SUCCESS;
}

/*
 * Remove a dynamically added /32 server route from a protection group.
 */
sai_status_t EvpnMhOrch::removeHwFrrServerRoute(const std::string &es_port, const IpAddress &server_ip)
{
    SWSS_LOG_ENTER();

    auto state_it = m_hwFrrState.find(es_port);
    if (state_it == m_hwFrrState.end())
    {
        return SAI_STATUS_SUCCESS;
    }

    EsHwFrrState &state = state_it->second;
    sai_object_id_t vrf_oid = getVrfOidForEsPort(es_port);

    for (auto it = state.server_routes.begin(); it != state.server_routes.end(); ++it)
    {
        if (it->server_ip.getIp() == server_ip && it->owns_route && vrf_oid != SAI_NULL_OBJECT_ID)
        {
            sai_route_entry_t route_entry;
            route_entry.switch_id = gSwitchId;
            route_entry.vr_id = vrf_oid;
            route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

            std::string ip_str = server_ip.to_string();
            inet_pton(AF_INET, ip_str.c_str(), &route_entry.destination.addr.ip4);
            inet_pton(AF_INET, "255.255.255.255", &route_entry.destination.mask.ip4);

            sai_status_t status = sai_route_api->remove_route_entry(&route_entry);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("removeHwFrrServerRoute: failed to remove route %s for %s (status=%d)",
                               ip_str.c_str(), es_port.c_str(), status);
            }
            else
            {
                SWSS_LOG_NOTICE("removeHwFrrServerRoute: removed %s for ES %s",
                                ip_str.c_str(), es_port.c_str());
            }

            state.server_routes.erase(it);
            return status;
        }
    }

    return SAI_STATUS_SUCCESS;
}
