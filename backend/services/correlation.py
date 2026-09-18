"""
Forensic Correlation Service.
Correlates Evidence, IOCs, Processes, Users, IPs, Domains, and Timeline events
into an entity-relationship topology graph for interactive visualization.
SIH1744 • SIH 2024
"""

from typing import List, Dict, Any, Tuple, Set


def correlate_entities_and_relationships(
    evidence_list: List[Dict[str, Any]],
    ioc_list: List[Dict[str, Any]],
    events_list: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Builds a graph topology with nodes and links representing correlations between forensic items.
    """
    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []
    seen_nodes: Set[str] = set()
    seen_links: Set[Tuple[str, str, str]] = set()

    def add_node(node_id: str, label: str, category: str, risk: str = "LOW", details: str = ""):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "category": category,
                "risk": risk,
                "details": details
            })

    def add_link(src: str, tgt: str, label: str, rel_type: str = "associated"):
        if src in seen_nodes and tgt in seen_nodes and src != tgt:
            key = (src, tgt, label)
            if key not in seen_links:
                seen_links.add(key)
                links.append({
                    "source": src,
                    "target": tgt,
                    "label": label,
                    "type": rel_type
                })

    # Process evidence records
    for ev in evidence_list:
        ev_id = ev.get("id") or f"ev_{len(nodes)}"
        name = ev.get("name") or ev.get("filename") or ev_id
        ev_type = ev.get("type") or ev.get("evidence_type") or "File"
        risk_tier = ev.get("risk_tier") or ("CRITICAL" if (ev.get("risk_score") or 0) >= 80 else "HIGH" if (ev.get("risk_score") or 0) >= 60 else "LOW")
        desc = ev.get("description") or ""

        # Map type to category
        category = "File"
        if ev_type in ("Network", "IP"):
            category = "Network"
        elif ev_type in ("Process",):
            category = "Process"
        elif ev_type in ("User",):
            category = "User"
        elif ev_type in ("System",):
            category = "System"
        elif ev_type in ("Browser", "Domain"):
            category = "Domain"

        add_node(ev_id, name, category, risk_tier, desc)

        # Correlate user if present
        user_name = ev.get("user")
        if user_name and user_name != "N/A":
            user_id = f"user_{user_name.replace('\\', '_').replace('/', '_').replace('.', '_')}"
            add_node(user_id, f"User: {user_name}", "User", "LOW", f"User context associated with {ev_id}")
            add_link(user_id, ev_id, "OPERATED", "interaction")

        # Correlate parent process if present
        parent = ev.get("parentProcess") or ev.get("parent_process")
        if parent and parent != "N/A":
            parent_id = f"proc_{parent.replace('.', '_')}"
            add_node(parent_id, parent, "Process", "HIGH" if "updater" in parent else "LOW", f"Parent process for {name}")
            add_link(parent_id, ev_id, "SPAWNED", "execution")

        # Correlate destination IP if present
        dest_ip = ev.get("destinationIp") or ev.get("destination_ip")
        if dest_ip and dest_ip != "N/A":
            ip_id = f"ip_{dest_ip.replace('.', '_')}"
            is_c2 = any(dest_ip.startswith(p) for p in ("185.220.", "91.240."))
            add_node(ip_id, f"{dest_ip} (C2)" if is_c2 else dest_ip, "Network", "CRITICAL" if is_c2 else "MEDIUM", f"Network connection from {ev_id}")
            add_link(ev_id, ip_id, "C2_BEACON" if is_c2 else "CONNECTED", "network")

    # Correlate IOCs
    for ioc in ioc_list:
        val = ioc.get("value") or ioc.get("ioc") or ""
        ioc_type = ioc.get("ioc_type") or ioc.get("type") or "IOC"
        risk = ioc.get("risk") or "MEDIUM"
        status = ioc.get("status") or "Discovered IOC"

        if not val:
            continue

        if "Domain" in ioc_type or "URL" in ioc_type:
            dom_id = f"dom_{val.split('/')[0].replace('.', '_').replace(':', '_')}"
            add_node(dom_id, val, "Domain", risk, status)
        elif "IP" in ioc_type:
            ip_id = f"ip_{val.replace('.', '_')}"
            add_node(ip_id, val, "Network", risk, status)

    return {
        "nodes": nodes,
        "links": links,
        "edges": links  # Provided for schema compatibility
    }
