#include "evpnmhorch.h"

#include <inttypes.h>
#include <arpa/inet.h>
#include <set>

#include "portsorch.h"
#include "directory.h"
#include "vxlanorch.h"
#include "vrforch.h"
#include "schema.h"
#include "dbconnector.h"
#include "table.h"

extern PortsOrch *gPortsOrch;
extern Directory<Orch*> gDirectory;
/* No gAppDb global — use local DBConnector in initPeerState */

extern sai_vlan_api_t *sai_vlan_api;
extern sai_next_hop_api_t *sai_next_hop_api;
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
            }
            if (!vlanMembersApplyNonDF(key))
            {
                // SAI operation failed — ES is registered but DF state
                // not applied.  Leave in m_toSync for retry.
                ++it;
                continue;
            }
        }
        else if (op == DEL_COMMAND)
        {
            m_esIntfMap.erase(key);
            m_esFailoverMode.erase(key);
            m_esPeerVtep.erase(key);
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
    else
    {
        if (table_name == "EVPN_ETHERNET_SEGMENT")
        {
            doEvpnEsIntfTask(consumer);
        }
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
