/*
 * evpnmhorch.cpp — EVPN MH v2.0 simplified orchestrator
 *
 * In v2.0, all failover logic (PROTECTION NHG, /32 routes, tunnel reroute)
 * moves into VPP via the es-protect virtual interface. This orch only handles:
 *   - DF (Designated Forwarder) election from FRR
 *   - ES interface association tracking
 *
 * Removed from v1.0:
 *   - PROTECTION NHG creation/management
 *   - /32 server route injection
 *   - L2/L3/HW failover mode selection
 *   - Tunnel reroute on port down/up
 *   - ES state table processing (now consumed by VPP-SAI directly)
 */

#include "evpnmhorch.h"

#include <inttypes.h>
#include <set>
#include <sstream>

#include "portsorch.h"
#include "schema.h"

extern PortsOrch *gPortsOrch;
extern sai_vlan_api_t *sai_vlan_api;

#define VLAN_PREFIX "Vlan"

EvpnMhOrch::EvpnMhOrch(vector<TableConnector> &connectors) : Orch(connectors)
{
    SWSS_LOG_ENTER();
}

EvpnMhOrch::~EvpnMhOrch()
{
    SWSS_LOG_ENTER();
    for (auto &entry : m_esDataMap)
        delete entry.second;
}

struct EsCacheEntry *EvpnMhOrch::getEsCache(const std::string &key)
{
    auto it = m_esDataMap.find(key);
    return (it != m_esDataMap.end()) ? it->second : nullptr;
}

struct EsCacheEntry *EvpnMhOrch::getEsCacheForPort(const std::string &key)
{
    for (const auto &entry : m_esDataMap)
    {
        if (entry.first.find(key) != std::string::npos)
            return entry.second;
    }
    return nullptr;
}

static std::string getPortFromEsKey(const std::string &key)
{
    auto pos = key.find(':');
    return (pos != std::string::npos) ? key.substr(pos + 1) : "Unknown";
}

std::string EvpnMhOrch::stripVlanFromInterfaceName(const std::string interfaceName)
{
    auto pos = interfaceName.find(':');
    return (pos != std::string::npos) ? interfaceName.substr(pos + 1) : interfaceName;
}

bool EvpnMhOrch::updateEsCache(string &key, KeyOpFieldsValuesTuple &t)
{
    bool is_df = false;

    for (const auto &i : kfvFieldsValues(t))
    {
        if (fvField(i) == "df")
        {
            is_df = (fvValue(i) == "true");
            break;
        }
    }

    EsCacheEntry *existing = getEsCache(key);
    if (existing)
    {
        existing->is_df = is_df;
    }
    else
    {
        existing = new EsCacheEntry(is_df);
        m_esDataMap[key] = existing;
    }

    std::string port_name = getPortFromEsKey(key);
    std::string vlan_id_str;
    auto pos = key.find(':');
    if (pos != std::string::npos)
        vlan_id_str = key.substr(0, pos);

    SWSS_LOG_NOTICE("updateEsCache: SET %s, port: %s, is_df: %d",
                    key.c_str(), port_name.c_str(), existing->is_df);

    Port port;
    sai_object_id_t vlan_member_id;

    if (!gPortsOrch->getPort(vlan_id_str, port))
    {
        SWSS_LOG_ERROR("updateEsCache: VLAN %s not found", vlan_id_str.c_str());
        return false;
    }

    if (gPortsOrch->getVlanMember(port_name, port, vlan_member_id))
    {
        sai_attribute_t attr;
        attr.id = SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP;
        attr.value.booldata = existing->is_df;

        auto status = sai_vlan_api->set_vlan_member_attribute(vlan_member_id, &attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("updateEsCache: failed to set DF attr for %s (status=%d)",
                          key.c_str(), status);
            return false;
        }
    }
    else
    {
        SWSS_LOG_ERROR("updateEsCache: VLAN member not found for %s", key.c_str());
        return false;
    }
    return true;
}

bool EvpnMhOrch::deleteEsCache(string &key)
{
    EsCacheEntry *entry = getEsCache(key);
    if (!entry)
        return true;

    SWSS_LOG_NOTICE("deleteEsCache: DEL %s", key.c_str());

    std::string port_name = getPortFromEsKey(key);
    std::string vlan_id_str;
    auto pos = key.find(':');
    if (pos != std::string::npos)
        vlan_id_str = key.substr(0, pos);

    Port port;
    sai_object_id_t vlan_member_id;

    if (gPortsOrch->getPort(vlan_id_str, port) &&
        gPortsOrch->getVlanMember(port_name, port, vlan_member_id))
    {
        sai_attribute_t attr;
        attr.id = SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP;
        attr.value.booldata = false;
        sai_vlan_api->set_vlan_member_attribute(vlan_member_id, &attr);
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
        return false;

    gPortsOrch->getPortVlanMembers(port, vlan_members);
    for (const auto &member : vlan_members)
    {
        sai_attribute_t attr;
        attr.id = SAI_VLAN_MEMBER_ATTR_TUNNEL_TERM_BUM_TX_DROP;
        attr.value.booldata = isInterfaceDF(port_name, member.first);
        sai_vlan_api->set_vlan_member_attribute(member.second.vlan_member_id, &attr);
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

        SWSS_LOG_NOTICE("doEvpnEsIntfTask: %s %s", op.c_str(), key.c_str());

        if (op == SET_COMMAND)
        {
            m_esIntfMap[key] = true;
            vlanMembersApplyNonDF(key);
        }
        else if (op == DEL_COMMAND)
        {
            m_esIntfMap.erase(key);
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
            success = updateEsCache(key, t);
        else if (op == DEL_COMMAND)
            success = deleteEsCache(key);

        if (!success)
            ++it;
        else
            it = consumer.m_toSync.erase(it);
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
    /* EVPN_MH_ES_STATE_TABLE: no longer processed here.
     * VPP-SAI reads it directly for standby ECMP updates. */
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
