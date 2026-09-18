/**
 * CYBER TRIAGE TOOL - SIH1744
 * Investigation Graph Engine
 * High-performance, pure SVG interactive network graph with pan, zoom,
 * node dragging, connected component highlighting, and detail inspection.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  if (!window.CyberTriageStore) {
    console.error('CyberTriageStore not found.');
    return;
  }

  const viewport = document.getElementById('graphViewport');
  const svg = document.getElementById('graphSvg');
  const transformGroup = document.getElementById('graphTransformGroup');
  const linksGroup = document.getElementById('graphLinksGroup');
  const nodesGroup = document.getElementById('graphNodesGroup');

  // Controls & Inspector
  const zoomInBtn = document.getElementById('zoomInBtn');
  const zoomOutBtn = document.getElementById('zoomOutBtn');
  const centerBtn = document.getElementById('centerGraphBtn');
  const resetZoomBtn = document.getElementById('resetZoomBtn');
  const realignBtn = document.getElementById('realignGraphBtn');
  const inspector = document.getElementById('nodeInspector');
  const closeInspectorBtn = document.getElementById('closeInspectorBtn');

  // Category Colors
  const CATEGORY_COLORS = {
    'User': '#3b82f6',
    'Process': '#a855f7',
    'File': '#eab308',
    'Network': '#ef4444',
    'Domain': '#f97316',
    'System': '#06b6d4'
  };

  const graphData = window.CyberTriageStore.getGraphData();
  const nodes = graphData.nodes;
  const links = graphData.links;

  // Viewport transformation state
  let panX = 50;
  let panY = 60;
  let scale = 0.72;

  let isPanning = false;
  let startX = 0;
  let startY = 0;
  let selectedNodeId = null;

  // Initial layout calculation (Layered attack topology flow)
  function initPositions() {
    const layoutLevels = [
      ['user_jdoe'],
      ['app_chrome'],
      ['dom_phish'],
      ['file_dropper'],
      ['file_updater'],
      ['proc_ps'],
      ['ip_c2_main', 'proc_cmd'],
      ['task_persist', 'file_lsass_dmp'],
      ['user_da', 'file_exfil_7z'],
      ['host_dc01', 'ip_exfil_target', 'user_backdoor']
    ];

    const xSpacing = 160;
    const ySpacing = 120;

    layoutLevels.forEach((lvl, lvlIdx) => {
      const startX = 100 + lvlIdx * xSpacing;
      const totalInLvl = lvl.length;
      const startY = 320 - ((totalInLvl - 1) * ySpacing) / 2;

      lvl.forEach((nodeId, nodeIdx) => {
        const n = nodes.find(item => item.id === nodeId);
        if (n) {
          n.x = startX;
          n.y = startY + nodeIdx * ySpacing;
        }
      });
    });

    // Fallback for any unpositioned node
    nodes.forEach((n, idx) => {
      if (typeof n.x === 'undefined') {
        n.x = 200 + (idx % 4) * 160;
        n.y = 150 + Math.floor(idx / 4) * 110;
      }
    });
  }

  initPositions();

  function updateTransform() {
    if (transformGroup) {
      transformGroup.setAttribute('transform', `translate(${panX}, ${panY}) scale(${scale})`);
    }
  }

  function renderGraph() {
    if (!linksGroup || !nodesGroup) return;

    linksGroup.innerHTML = '';
    nodesGroup.innerHTML = '';

    // Render Links
    links.forEach(link => {
      const sourceNode = nodes.find(n => n.id === link.source);
      const targetNode = nodes.find(n => n.id === link.target);
      if (!sourceNode || !targetNode) return;

      const isHighlighted = selectedNodeId && (link.source === selectedNodeId || link.target === selectedNodeId);
      const isDimmed = selectedNodeId && !isHighlighted;

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', sourceNode.x);
      line.setAttribute('y1', sourceNode.y);
      line.setAttribute('x2', targetNode.x);
      line.setAttribute('y2', targetNode.y);
      line.setAttribute('stroke', isHighlighted ? '#ff2a2a' : (isDimmed ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.25)'));
      line.setAttribute('stroke-width', isHighlighted ? '2.5' : '1.5');
      line.setAttribute('marker-end', isDimmed ? 'url(#arrowhead-dim)' : 'url(#arrowhead)');
      line.setAttribute('data-source', link.source);
      line.setAttribute('data-target', link.target);

      // Label on link
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      const midX = (sourceNode.x + targetNode.x) / 2;
      const midY = (sourceNode.y + targetNode.y) / 2;
      text.setAttribute('x', midX);
      text.setAttribute('y', midY - 6);
      text.setAttribute('fill', isHighlighted ? '#ff4747' : (isDimmed ? 'rgba(255,255,255,0.15)' : 'rgba(255,255,255,0.5)'));
      text.setAttribute('font-size', '9');
      text.setAttribute('font-family', 'JetBrains Mono, monospace');
      text.setAttribute('text-anchor', 'middle');
      text.textContent = link.label;

      linksGroup.appendChild(line);
      linksGroup.appendChild(text);
    });

    // Render Nodes
    nodes.forEach(node => {
      const isSelected = node.id === selectedNodeId;
      const isConnected = selectedNodeId && links.some(l => 
        (l.source === selectedNodeId && l.target === node.id) || 
        (l.target === selectedNodeId && l.source === node.id)
      );
      const isDimmed = selectedNodeId && !isSelected && !isConnected;

      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', `translate(${node.x}, ${node.y})`);
      g.setAttribute('style', 'cursor: pointer;');
      g.setAttribute('data-id', node.id);

      const color = CATEGORY_COLORS[node.category] || '#ffffff';

      // Outer glow / selection ring
      if (isSelected || isConnected) {
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', isSelected ? '26' : '22');
        ring.setAttribute('fill', 'none');
        ring.setAttribute('stroke', isSelected ? '#ff2a2a' : color);
        ring.setAttribute('stroke-width', '2');
        ring.setAttribute('stroke-dasharray', isSelected ? '4 2' : 'none');
        ring.setAttribute('opacity', '0.8');
        g.appendChild(ring);
      }

      // Main Circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', '18');
      circle.setAttribute('fill', isDimmed ? '#14171f' : '#0d0f14');
      circle.setAttribute('stroke', isDimmed ? 'rgba(255,255,255,0.1)' : color);
      circle.setAttribute('stroke-width', isSelected ? '3' : '2');
      circle.setAttribute('opacity', isDimmed ? '0.35' : '1');
      g.appendChild(circle);

      // Node Icon / Abbreviation
      const abbr = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      abbr.setAttribute('y', '4');
      abbr.setAttribute('fill', isDimmed ? 'rgba(255,255,255,0.3)' : color);
      abbr.setAttribute('font-size', '10');
      abbr.setAttribute('font-weight', '700');
      abbr.setAttribute('font-family', 'JetBrains Mono, monospace');
      abbr.setAttribute('text-anchor', 'middle');
      abbr.textContent = node.category.substring(0, 3).toUpperCase();
      g.appendChild(abbr);

      // Label below node
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('y', '32');
      label.setAttribute('fill', isDimmed ? 'rgba(255,255,255,0.2)' : '#ffffff');
      label.setAttribute('font-size', '11');
      label.setAttribute('font-weight', isSelected ? '700' : '500');
      label.setAttribute('font-family', 'Inter, sans-serif');
      label.setAttribute('text-anchor', 'middle');
      label.textContent = node.label;
      g.appendChild(label);

      // Dragging & Clicking handlers
      let isDragging = false;
      let dragStartX = 0;
      let dragStartY = 0;

      g.addEventListener('mousedown', (e) => {
        e.stopPropagation();
        isDragging = true;
        dragStartX = e.clientX;
        dragStartY = e.clientY;
      });

      window.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        const dx = (e.clientX - dragStartX) / scale;
        const dy = (e.clientY - dragStartY) / scale;
        node.x += dx;
        node.y += dy;
        dragStartX = e.clientX;
        dragStartY = e.clientY;
        renderGraph();
      });

      window.addEventListener('mouseup', () => {
        isDragging = false;
      });

      g.addEventListener('click', (e) => {
        e.stopPropagation();
        selectNode(node);
      });

      nodesGroup.appendChild(g);
    });
  }

  function selectNode(node) {
    if (selectedNodeId === node.id) {
      selectedNodeId = null;
      if (inspector) inspector.style.display = 'none';
    } else {
      selectedNodeId = node.id;
      showInspector(node);
    }
    renderGraph();
  }

  function showInspector(node) {
    if (!inspector) return;

    document.getElementById('inspectNodeType').textContent = node.category;
    document.getElementById('inspectNodeTitle').textContent = node.label;
    document.getElementById('inspectNodeDesc').textContent = node.details || 'Entity observed in triage telemetry.';
    
    const riskBadge = document.getElementById('inspectNodeRisk');
    riskBadge.textContent = node.risk;
    riskBadge.className = `badge badge-${node.risk.toLowerCase()}`;

    // Find connected links
    const connGroup = document.getElementById('inspectNodeConnections');
    connGroup.innerHTML = '';

    const connectedLinks = links.filter(l => l.source === node.id || l.target === node.id);
    connectedLinks.forEach(l => {
      const isOut = l.source === node.id;
      const otherId = isOut ? l.target : l.source;
      const otherNode = nodes.find(n => n.id === otherId);
      if (!otherNode) return;

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip-btn font-mono';
      btn.style.justifyContent = 'space-between';
      btn.style.width = '100%';
      btn.innerHTML = `
        <span>${isOut ? '&rarr;' : '&larr;'} ${l.label}</span>
        <span style="color: var(--text-white); font-weight:700;">${otherNode.label}</span>
      `;
      btn.addEventListener('click', () => {
        selectNode(otherNode);
      });
      connGroup.appendChild(btn);
    });

    inspector.style.display = 'flex';
  }

  if (closeInspectorBtn) {
    closeInspectorBtn.addEventListener('click', () => {
      selectedNodeId = null;
      inspector.style.display = 'none';
      renderGraph();
    });
  }

  // Pan interaction
  viewport.addEventListener('mousedown', (e) => {
    if (e.target === svg || e.target.tagName === 'line' || e.target.id === 'graphViewport') {
      isPanning = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
    }
  });

  window.addEventListener('mousemove', (e) => {
    if (!isPanning) return;
    panX = e.clientX - startX;
    panY = e.clientY - startY;
    updateTransform();
  });

  window.addEventListener('mouseup', () => {
    isPanning = false;
  });

  // Zoom interaction via wheel
  viewport.addEventListener('wheel', (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1;
    scale = Math.min(2.5, Math.max(0.3, scale * zoomFactor));
    updateTransform();
  });

  // Control buttons
  if (zoomInBtn) {
    zoomInBtn.addEventListener('click', () => {
      scale = Math.min(2.5, scale * 1.2);
      updateTransform();
    });
  }

  if (zoomOutBtn) {
    zoomOutBtn.addEventListener('click', () => {
      scale = Math.max(0.3, scale / 1.2);
      updateTransform();
    });
  }

  if (centerBtn) {
    centerBtn.addEventListener('click', () => {
      panX = 50;
      panY = 60;
      scale = 0.72;
      updateTransform();
    });
  }

  if (resetZoomBtn) {
    resetZoomBtn.addEventListener('click', () => {
      panX = 50;
      panY = 60;
      scale = 0.72;
      updateTransform();
    });
  }

  if (realignBtn) {
    realignBtn.addEventListener('click', () => {
      initPositions();
      selectedNodeId = null;
      if (inspector) inspector.style.display = 'none';
      panX = 50;
      panY = 60;
      scale = 0.72;
      updateTransform();
      renderGraph();
      if (window.showAppToast) window.showAppToast('TOPOLOGY AUTO-LAYOUT RECALCULATED');
    });
  }

  // Click on background deselects
  svg.addEventListener('click', (e) => {
    if (e.target === svg) {
      selectedNodeId = null;
      if (inspector) inspector.style.display = 'none';
      renderGraph();
    }
  });

  // Initial draw
  updateTransform();
  renderGraph();
});
